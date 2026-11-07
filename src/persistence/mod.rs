//! Single-writer state and transactional audit. Never stores private material.
pub mod catalog;
pub mod checkpoint;
pub mod clock;
pub mod grants;
pub(crate) mod policy;
pub mod projection;
pub mod requests;

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Duration;

use rand::RngCore;
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{KeydError, Result};
use crate::principal::Principal;
use crate::security::config::ServiceConfig;
use clock::Time;

const SCHEMA: i64 = 5;
const APPLICATION: i64 = 0x414e504b;
pub(crate) const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Change {
    /// Switch to a pre-provisioned hot key and retire the old public method.
    RotateHotKey {
        root_key_id: String,
        old_key_id: String,
        next_key_id: String,
    },
    /// Add and/or retire non-binding methods, root-signed when the approval is
    /// completed. This is how a device joins or leaves: its signing and
    /// agreement keys are published or retired together.
    ReissueDocument {
        root_key_id: String,
        #[serde(default)]
        add: Vec<catalog::Addition>,
        #[serde(default)]
        remove: Vec<String>,
    },
    /// Mint a device-signing and a key-agreement key for a device that has none.
    ///
    /// The two envelopes are sealed with the passphrase that comes with the
    /// completion, so the same credential that unlocks root for `ReissueDocument`
    /// also decides how the new keys are wrapped. Nothing is published here:
    /// the pair joins the document through `ReissueDocument`, and only then
    /// gets a catalog row and a role.
    IssueDeviceKeys {
        root_key_id: String,
    },
    /// Exact awiki registration proof, authorized only through management.
    RegistrationChallenge {
        key_id: String,
        origin: String,
        challenge: String,
    },
    /// Mint a complete identity in one approved step: root plus one device's
    /// signing and agreement keys, their catalog rows, the policies that say
    /// what the identity may do, and the grants that hand those rights to the
    /// new keys.
    ///
    /// The passphrase comes with the completion, so one human confirmation
    /// both decides the identity and seals every envelope. Nothing is minted
    /// at prepare time.
    ProvisionIdentity {
        vault_id: Option<String>,
        host: String,
        port: Option<u16>,
        /// `e1_` 之前的路径段,例如 `["user", "<handle>"]`。
        path_segments: Vec<String>,
        /// `<agent>/<profile>`;文档里的设备 fragment 是 `{device}-sign` 与
        /// `{device}-agreement`。
        device_id: String,
        /// 默认取唯一一个 enabled principal。
        principal_uid: Option<u32>,
        policies: Vec<IdentityPolicy>,
        grants: Vec<IdentityGrant>,
        /// grant 的生命周期,默认 30 天。
        #[serde(default = "default_expiry_days")]
        expiry_days: u32,
        #[serde(default = "default_max_uses")]
        max_uses: u32,
    },
    RegisterPrincipal {
        uid: u32,
    },
    DisablePrincipal {
        principal_id: String,
    },
    /// Retire every key of a DID that never got a document installed.
    ///
    /// This is the cleanup for a provisioning that committed in the protected
    /// plane and then failed to publish or register. Keys move to `retired`
    /// and their grants to `revoked`; policies stay because another identity
    /// may reuse them. An identity that already has an installed document must
    /// go through deactivate/migrate instead.
    RetireIdentity {
        did: String,
    },
    /// Re-issue the grants a restart, expiry or exhausted quota took away.
    ///
    /// Each distinct (key, policy, kind) the principal already held is issued
    /// again with the same lifetime and use limit. A deliberately revoked
    /// grant (`grant revoke`) is never revived: only `revoked_restart`,
    /// `expired` and `exhausted` rows qualify.
    RefreshGrants {
        principal_id: String,
        did: String,
    },
    Catalog {
        change: catalog::CatalogChange,
    },
    Grant {
        change: grants::GrantChange,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Resolved {
    RotateHotKey {
        root: Box<catalog::KeyRecord>,
        old: Box<catalog::KeyRecord>,
        next: Box<catalog::KeyRecord>,
        unsigned: Value,
    },
    ReissueDocument {
        root: Box<catalog::KeyRecord>,
        add: Vec<catalog::Addition>,
        remove: Vec<String>,
        unsigned: Value,
    },
    IssueDeviceKeys {
        root: Box<catalog::KeyRecord>,
        sign: String,
        agreement: String,
    },
    ProvisionIdentity {
        vault_id: String,
        host: String,
        port: Option<u16>,
        path_segments: Vec<String>,
        device_id: String,
        principal_id: String,
        policies: Vec<ResolvedPolicy>,
        grants: Vec<ResolvedGrant>,
        expiry: i64,
        max_uses: u32,
    },
    RegistrationChallenge {
        key: Box<catalog::KeyRecord>,
        origin: String,
        challenge: String,
    },
    Grant {
        effect: grants::Effect,
    },
    RegisterPrincipal {
        uid: u32,
        principal_id: String,
        generation: u32,
    },
    DisablePrincipal {
        principal_id: String,
    },
    RetireIdentity {
        did: String,
        vault_id: String,
    },
    RefreshGrants {
        did: String,
        effects: Vec<grants::Effect>,
        /// The lost rows this refresh replaces. They become `revoked`, so a later
        /// deliberate revocation of the replacement cannot be undone by re-reading
        /// an old `revoked_restart` row.
        superseded: Vec<String>,
    },
    Catalog {
        effect: Box<catalog::CatalogEffect>,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prepared {
    pub operation_id: String,
    pub digest: String,
    pub effect: Value,
    pub expires_at: i64,
}

/// 一次 provision 要发布的一条策略。
///
/// `purpose` 接受 `http_authentication` 与 `http-authentication` 两种写法,
/// 落库前统一成策略 v2 自己的线上词。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPolicy {
    pub policy_id: String,
    pub name: String,
    pub purpose: String,
    pub limits: policy::Limits,
    pub content: Value,
}

/// 一条把策略授给本次新身份某把钥匙的 grant。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityGrant {
    pub policy_id: String,
    pub key: catalog::KeyRole,
}

/// 解析后的策略:内容已经过 `policy::normalize`,提交时原样落库。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedPolicy {
    policy_id: String,
    purpose: policy::Purpose,
    content: Value,
    /// grant 回复要用的名字(`http`、`origin_proof_agent`、…)。
    grant_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedGrant {
    grant_name: String,
    policy_id: String,
    key: catalog::KeyRole,
}

/// provision 已经写下的信封文件。
///
/// 事务提交之前出任何错(包括最后的期限复核),它们都必须删掉 —— 否则磁盘
/// 上会留下没有目录行的孤儿钥匙。
#[derive(Default)]
struct MintedFiles {
    paths: Vec<std::path::PathBuf>,
    keep: bool,
}
impl MintedFiles {
    fn push(&mut self, path: std::path::PathBuf) {
        self.paths.push(path);
    }
    fn keep(mut self) {
        self.keep = true;
    }
}
impl Drop for MintedFiles {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn provision_record(
    vault_id: &str,
    did: &str,
    wrapped: &crate::keystore::record::WrappedKey,
    role: catalog::KeyRole,
    purpose: &str,
) -> Result<catalog::KeyRecord> {
    Ok(catalog::KeyRecord {
        key_id: uuid(),
        vault_id: vault_id.to_owned(),
        did: did.to_owned(),
        kid: wrapped.id.kid.clone(),
        role,
        purpose: purpose.to_owned(),
        envelope_digest: envelope_digest(wrapped)?,
        document_digest: GENESIS.to_owned(),
        state: "active".into(),
        identity_epoch: 0,
        generation: 0,
    })
}

fn envelope_digest(wrapped: &impl Serialize) -> Result<String> {
    Ok(hex(&Sha256::digest(
        serde_json_canonicalizer::to_vec(wrapped).map_err(|_| invalid())?,
    )))
}

pub struct Database {
    connection: Connection,
    pub boot_epoch: i64,
    root: std::path::PathBuf,
}
fn db_error(_: rusqlite::Error) -> KeydError {
    unavailable()
}
fn unavailable() -> KeydError {
    KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into())
}
fn invalid() -> KeydError {
    KeydError::Misuse("ADMIN_OPERATION_INVALID".into())
}
fn default_expiry_days() -> u32 {
    30
}
fn default_max_uses() -> u32 {
    100
}

/// `http_authentication` 和 `http-authentication` 是同一个 purpose;落库的
/// 永远是策略 v2 的线上词。
fn identity_purpose(value: &str) -> Result<policy::Purpose> {
    let wire = value.replace('_', "-");
    let purpose: policy::Purpose = serde_json::from_value(Value::String(wire)).map_err(|_| invalid())?;
    if matches!(
        purpose,
        policy::Purpose::ObjectProof | policy::Purpose::Root
    ) {
        return Err(invalid());
    }
    Ok(purpose)
}

/// grant 在回包与 attach 命令里的名字。origin proof 按目标类别各算一条。
fn grant_name(purpose: policy::Purpose, content: &Value) -> Result<String> {
    let name = match purpose {
        policy::Purpose::HttpAuthentication => "http",
        policy::Purpose::DocumentProof => "document_proof",
        policy::Purpose::PurposeSigning => "purpose",
        policy::Purpose::Ecdh => "ecdh",
        policy::Purpose::OriginProof => {
            let kind = content
                .get("content")
                .and_then(|c| c.get("origin"))
                .and_then(Value::as_str)
                .and_then(|origin| origin.strip_prefix("anp://"))
                .filter(|kind| crate::security::origin::TARGET_KINDS.contains(kind))
                .ok_or_else(invalid)?;
            return Ok(format!("origin_proof_{kind}"));
        }
        _ => return Err(invalid()),
    };
    Ok(name.to_string())
}

fn provision_effect(
    tx: &Connection,
    now: Time,
    vault_id: Option<String>,
    host: String,
    port: Option<u16>,
    path_segments: Vec<String>,
    device_id: String,
    principal_uid: Option<u32>,
    policies: Vec<IdentityPolicy>,
    grants: Vec<IdentityGrant>,
    expiry_days: u32,
    max_uses: u32,
) -> Result<Resolved> {
    let vault_id = match vault_id {
        Some(id) => id,
        None => {
            let ids: Vec<String> = {
                let mut statement = tx
                    .prepare("SELECT vault_id FROM vaults WHERE state='active'")
                    .map_err(db_error)?;
                let rows = statement
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(db_error)?
                    .collect::<std::result::Result<_, _>>()
                    .map_err(db_error)?;
                rows
            };
            match ids.len() {
                1 => ids.into_iter().next().ok_or_else(invalid)?,
                _ => return Err(invalid()),
            }
        }
    };
    let active: Option<String> = tx
        .query_row(
            "SELECT state FROM vaults WHERE vault_id=?1",
            [&vault_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?;
    if active.as_deref() != Some("active") {
        return Err(invalid());
    }

    crate::did::parse::check_host(&host)?;
    if path_segments.is_empty() {
        return Err(invalid());
    }
    for segment in &path_segments {
        crate::did::parse::check_path_segment(segment)?;
    }
    let device_parts: Vec<&str> = device_id.split('/').collect();
    if device_parts.len() != 2
        || device_parts.iter().any(|part| {
            part.is_empty()
                || part.len() > 128
                || part.chars().any(char::is_control)
                || part.contains('#')
                || part.contains(':')
        })
    {
        return Err(invalid());
    }

    let principal_id: String = match principal_uid {
        Some(uid) => tx
            .query_row(
                "SELECT principal_id FROM principals WHERE uid=?1 AND state='enabled'",
                [uid],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?
            .ok_or_else(invalid)?,
        None => {
            let ids: Vec<String> = {
                let mut statement = tx
                    .prepare("SELECT principal_id FROM principals WHERE state='enabled'")
                    .map_err(db_error)?;
                let rows = statement
                    .query_map([], |r| r.get::<_, String>(0))
                    .map_err(db_error)?
                    .collect::<std::result::Result<_, _>>()
                    .map_err(db_error)?;
                rows
            };
            match ids.len() {
                1 => ids.into_iter().next().ok_or_else(invalid)?,
                _ => return Err(invalid()),
            }
        }
    };

    // 精确 DID 要等根公钥生成才知道;准备阶段只知道坐标。同一个坐标下已有
    // 一把 active 签名键,这个身份就重复了。
    let base = match port {
        Some(port) => format!("did:wba:{}%3A{}", host, port),
        None => format!("did:wba:{}", host),
    };
    let prefix = format!("{base}:{}:e1_", path_segments.join(":"));
    let dids: Vec<String> = {
        let mut statement = tx
            .prepare("SELECT DISTINCT did FROM keys WHERE vault_id=?1 AND state='active'")
            .map_err(db_error)?;
        let rows = statement
            .query_map([&vault_id], |r| r.get::<_, String>(0))
            .map_err(db_error)?
            .collect::<std::result::Result<_, _>>()
            .map_err(db_error)?;
        rows
    };
    if dids.iter().any(|did| did.starts_with(&prefix)) {
        return Err(invalid());
    }

    if expiry_days == 0 || expiry_days > 365 || max_uses == 0 {
        return Err(invalid());
    }
    let expiry = now
        .wall
        .checked_add(i64::from(expiry_days) * 86_400)
        .ok_or_else(invalid)?;

    let mut policy_ids = BTreeSet::new();
    let mut resolved_policies = Vec::with_capacity(policies.len());
    for p in policies {
        if !crate::principal::validate_uuid(&p.policy_id) || !policy_ids.insert(p.policy_id.clone()) {
            return Err(invalid());
        }
        let purpose = identity_purpose(&p.purpose)?;
        let content = json!({
            "schema_version": 2,
            "name": p.name,
            "purpose": purpose,
            "limits": p.limits,
            "content": p.content,
        });
        let normalized = policy::normalize(content)?;
        if purpose == policy::Purpose::PurposeSigning {
            let purposes = normalized
                .get("content")
                .and_then(|c| c.get("purposes"))
                .and_then(Value::as_array)
                .ok_or_else(invalid)?;
            if purposes.iter().any(|name| {
                name.as_str()
                    .is_none_or(|name| !catalog::purpose_valid(&catalog::KeyRole::DeviceSigning, name))
            }) {
                return Err(invalid());
            }
        }
        if i64::from(p.limits.max_duration_seconds) < expiry.saturating_sub(now.wall)
            || p.limits.max_uses < max_uses
        {
            return Err(invalid());
        }
        resolved_policies.push(ResolvedPolicy {
            policy_id: p.policy_id,
            grant_name: grant_name(purpose, &normalized)?,
            purpose,
            content: normalized,
        });
    }

    if grants.is_empty() {
        return Err(invalid());
    }
    let mut names = BTreeSet::new();
    let mut resolved_grants = Vec::with_capacity(grants.len());
    for g in grants {
        let p = resolved_policies
            .iter()
            .find(|p| p.policy_id == g.policy_id)
            .ok_or_else(invalid)?;
        let expected = match p.purpose {
            policy::Purpose::DocumentProof => catalog::KeyRole::Root,
            policy::Purpose::Ecdh => catalog::KeyRole::KeyAgreement,
            _ => catalog::KeyRole::DeviceSigning,
        };
        if g.key != expected || !names.insert(p.grant_name.clone()) {
            return Err(invalid());
        }
        resolved_grants.push(ResolvedGrant {
            grant_name: p.grant_name.clone(),
            policy_id: g.policy_id,
            key: g.key,
        });
    }

    Ok(Resolved::ProvisionIdentity {
        vault_id,
        host,
        port,
        path_segments,
        device_id,
        principal_id,
        policies: resolved_policies,
        grants: resolved_grants,
        expiry,
        max_uses,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn uuid() -> String {
    let mut bytes = [0; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let s = hex(&bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    )
}
fn capacity(connection: &Connection, pages: u32) -> Result<()> {
    let actual: u32 = connection
        .query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))
        .map_err(db_error)?;
    if actual != pages {
        return Err(unavailable());
    }
    Ok(())
}
fn settings(connection: &Connection) -> Result<()> {
    connection
        .busy_timeout(Duration::from_millis(500))
        .map_err(db_error)?;
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;").map_err(db_error)?;
    let foreign: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .map_err(db_error)?;
    let sync: i64 = connection
        .query_row("PRAGMA synchronous", [], |r| r.get(0))
        .map_err(db_error)?;
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .map_err(db_error)?;
    if foreign != 1 || sync != 3 || journal != "delete" {
        return Err(unavailable());
    }
    Ok(())
}

impl Database {
    /// Explicit, exclusive creation. Failed initialization leaves a maintenance
    /// artifact instead of silently replacing it with a new empty database.
    pub fn initialize(config: &ServiceConfig, now: Time) -> Result<()> {
        config.validate()?;
        if crate::daemon::self_uid() != config.service_uid {
            return Err(unavailable());
        }
        crate::security::paths::state_directory(&config.state_dir, config.service_uid)?;
        local_filesystem(&config.state_dir)?;
        let _lock = crate::security::paths::instance_lock(&config.state_dir, config.service_uid)?;
        let path = config.state_dir.join("state.sqlite");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&path)?;
        let mut connection = open_new(&path)?;
        Self::create(&mut connection, config, now)?;
        file.sync_all()?;
        managed_marker(&config.state_dir, &config.instance_id)?;
        std::fs::File::open(&config.state_dir)?.sync_all()?;
        Ok(())
    }

    fn create(connection: &mut Connection, config: &ServiceConfig, now: Time) -> Result<()> {
        capacity(connection, config.limits.database_max_pages)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        tx.execute_batch(include_str!("schema.sql"))
            .map_err(db_error)?;
        tx.execute(
            "INSERT INTO service_meta VALUES(1,?1,?2,0,0)",
            params![SCHEMA, config.instance_id],
        )
        .map_err(db_error)?;
        for principal in &config.principals {
            tx.execute(
                "INSERT INTO principals VALUES(?1,?2,?3,?4,?5)",
                params![
                    principal.principal_id,
                    principal.uid,
                    principal.generation,
                    if principal.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    now.wall
                ],
            )
            .map_err(db_error)?;
        }
        for id in &config.vault_ids {
            tx.execute(
                "INSERT INTO vaults VALUES(?1,?2,'active')",
                params![id, format!("vaults/{id}")],
            )
            .map_err(db_error)?;
        }
        tx.pragma_update(None, "application_id", APPLICATION)
            .map_err(db_error)?;
        tx.pragma_update(None, "user_version", SCHEMA)
            .map_err(db_error)?;
        append(
            &tx,
            &json!({"event":"INITIALIZED","instance_id":config.instance_id,"at":now.wall}),
        )?;
        tx.commit().map_err(db_error)
    }

    /// The caller must hold the service instance lock for this connection's life.
    pub fn recover(config: &ServiceConfig, now: Time) -> Result<Self> {
        crate::security::paths::state_directory(&config.state_dir, config.service_uid)?;
        local_filesystem(&config.state_dir)?;
        let path = config.state_dir.join("state.sqlite");
        let meta = std::fs::symlink_metadata(&path)?;
        if !meta.is_file()
            || meta.uid() != config.service_uid
            || meta.mode() & 0o777 != 0o600
            || meta.nlink() != 1
        {
            return Err(unavailable());
        }
        let mut db = Self {
            connection: open(&path)?,
            boot_epoch: 0,
            root: config.state_dir.clone(),
        };
        db.recovery(config, now)?;
        managed_marker(&config.state_dir, &config.instance_id)?;
        Ok(db)
    }

    fn recovery(&mut self, config: &ServiceConfig, now: Time) -> Result<()> {
        capacity(&self.connection, config.limits.database_max_pages)?;
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db_error)?;
        let app: i64 = self
            .connection
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(db_error)?;
        if !(1..=SCHEMA).contains(&version) || app != APPLICATION {
            return Err(unavailable());
        }
        let integrity: String = self
            .connection
            .query_row("PRAGMA integrity_check(1)", [], |r| r.get(0))
            .map_err(db_error)?;
        if integrity != "ok"
            || self
                .connection
                .prepare("PRAGMA foreign_key_check")
                .map_err(db_error)?
                .exists([])
                .map_err(db_error)?
        {
            return Err(unavailable());
        }
        verify_audit(&self.connection)?;
        let (instance, stored_schema): (String, i64) = self
            .connection
            .query_row(
                "SELECT instance_id,schema_version FROM service_meta WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_error)?;
        if instance != config.instance_id || stored_schema != version {
            return Err(unavailable());
        }
        if version == 1 {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_error)?;
            tx.execute_batch(include_str!("migration-v2.sql"))
                .map_err(db_error)?;
            append(
                &tx,
                &json!({"event":"SCHEMA_MIGRATED","from":1,"to":2,"at":now.wall}),
            )?;
            tx.commit().map_err(db_error)?;
        }
        if version < 3 {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_error)?;
            tx.execute_batch(include_str!("migration-v3.sql"))
                .map_err(db_error)?;
            append(
                &tx,
                &json!({"event":"SCHEMA_MIGRATED","from":2,"to":3,"at":now.wall}),
            )?;
            tx.commit().map_err(db_error)?;
        }
        if version < 4 {
            let tx = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_error)?;
            tx.execute_batch(include_str!("migration-v4.sql"))
                .map_err(db_error)?;
            append(
                &tx,
                &json!({"event":"SCHEMA_MIGRATED","from":3,"to":4,"at":now.wall}),
            )?;
            tx.commit().map_err(db_error)?;
        }
        if version < 5 {
            // The keys rebuild drops a table that grants reference, so the guard
            // has to be off outside the transaction; it is restored before the
            // next statement and the result is checked, not trusted.
            self.connection
                .pragma_update(None, "foreign_keys", false)
                .map_err(db_error)?;
            let migrated = (|| -> Result<()> {
                let tx = self
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(db_error)?;
                tx.execute_batch(include_str!("migration-v5.sql"))
                    .map_err(db_error)?;
                append(
                    &tx,
                    &json!({"event":"SCHEMA_MIGRATED","from":4,"to":5,"at":now.wall}),
                )?;
                tx.commit().map_err(db_error)
            })();
            self.connection
                .pragma_update(None, "foreign_keys", true)
                .map_err(db_error)?;
            migrated?;
            if self
                .connection
                .prepare("PRAGMA foreign_key_check")
                .map_err(db_error)?
                .exists([])
                .map_err(db_error)?
            {
                return Err(unavailable());
            }
        }
        catalog::recover_files(&mut self.connection, &self.root)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let (instance, schema): (String, i64) = tx
            .query_row(
                "SELECT instance_id,schema_version FROM service_meta WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(db_error)?;
        if instance != config.instance_id || schema != SCHEMA {
            return Err(unavailable());
        }
        for principal in config
            .admin_uids
            .iter()
            .chain(std::iter::once(&config.service_uid))
            .chain(std::iter::once(&0))
        {
            if tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM principals WHERE uid=?1 AND state='enabled')",
                    [principal],
                    |r| r.get::<_, bool>(0),
                )
                .map_err(db_error)?
            {
                return Err(unavailable());
            }
        }
        for id in &config.vault_ids {
            // A new vault is introduced only by the root-owned deployment
            // configuration while the service is offline. Validate its complete
            // public inventory, then bind registration and audit in this recovery
            // transaction. The migration tool never edits SQLite directly.
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM vaults WHERE vault_id=?1)",
                    [id],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if !exists {
                let inspection = crate::security::migration::inspect(&config.vault(id)?, false)?;
                tx.execute(
                    "INSERT INTO vaults VALUES(?1,?2,'active')",
                    params![id, format!("vaults/{id}")],
                )
                .map_err(db_error)?;
                append(
                    &tx,
                    &json!({"event":"MIGRATED_VAULT_REGISTERED","vault_id":id,"inspection":inspection}),
                )?;
            }
            let relative: String = tx
                .query_row(
                    "SELECT relative_path FROM vaults WHERE vault_id=?1 AND state='active'",
                    [id],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if relative != format!("vaults/{id}") {
                return Err(unavailable());
            }
        }
        tx.execute(
            "UPDATE service_meta SET boot_epoch=boot_epoch+1 WHERE singleton=1",
            [],
        )
        .map_err(db_error)?;
        self.boot_epoch = tx
            .query_row(
                "SELECT boot_epoch FROM service_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        tx.execute(
            "UPDATE grants SET state='revoked_restart' WHERE state='active'",
            [],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE requests SET state='outcome_unknown',result=NULL WHERE state='reserved'",
            [],
        )
        .map_err(db_error)?;
        tx.execute("UPDATE keys SET generation=generation+1", [])
            .map_err(db_error)?;
        tx.execute(
            "UPDATE admin_operations SET state='expired_restart' WHERE state='prepared'",
            [],
        )
        .map_err(db_error)?;
        append(
            &tx,
            &json!({"event":"BOOT_RECOVERED","boot_epoch":self.boot_epoch,"at":now.wall}),
        )?;
        tx.commit().map_err(db_error)
    }

    pub fn principal(&self, uid: u32) -> Result<Option<Principal>> {
        self.connection.query_row("SELECT principal_id,uid,generation FROM principals WHERE uid=?1 AND state='enabled'", [uid], |r| Ok(Principal { principal_id:r.get(0)?, uid:r.get(1)?, generation:r.get(2)?, enabled:true })).optional().map_err(db_error)
    }

    pub fn principals(&self) -> Result<Vec<Principal>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT principal_id,uid,generation,state FROM principals ORDER BY uid,generation",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([], |r| {
                Ok(Principal {
                    principal_id: r.get(0)?,
                    uid: r.get(1)?,
                    generation: r.get(2)?,
                    enabled: r.get::<_, String>(3)? == "enabled",
                })
            })
            .map_err(db_error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(db_error)
    }

    pub fn prepare(&mut self, actor: u32, change: Change, now: Time) -> Result<Prepared> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let root = self.root.clone();
        let resolved = match change {
            Change::RotateHotKey {
                root_key_id,
                old_key_id,
                next_key_id,
            } => {
                let root_key = catalog::get_key(&tx, &root_key_id)?;
                let old = catalog::get_key(&tx, &old_key_id)?;
                let next = catalog::get_key(&tx, &next_key_id)?;
                for key in [&root_key, &old, &next] {
                    catalog::validate_key(&root, key)?;
                    if key.state != "active"
                        || key.vault_id != root_key.vault_id
                        || key.did != root_key.did
                    {
                        return Err(invalid());
                    }
                }
                if root_key.role != catalog::KeyRole::Root
                    || old.role != catalog::KeyRole::Hot
                    || next.role != catalog::KeyRole::Hot
                    || old.key_id == next.key_id
                {
                    return Err(invalid());
                }
                let layout = crate::keystore::layout::KeydLayout::at(
                    root.join("vaults").join(&root_key.vault_id),
                );
                let doc = crate::keystore::store::read_did_document(&layout, &root_key.did)?;
                let unsigned = crate::did::lifecycle::remove_method(
                    &crate::did::lifecycle::strip_proof(&doc)?,
                    &old.kid,
                )?;
                Resolved::RotateHotKey {
                    root: Box::new(root_key),
                    old: Box::new(old),
                    next: Box::new(next),
                    unsigned,
                }
            }
            Change::RegistrationChallenge {
                key_id,
                origin,
                challenge,
            } => {
                let key = catalog::get_key(&tx, &key_id)?;
                catalog::validate_key(&root, &key)?;
                let target = crate::security::http::CanonicalHttpRequest::new(
                    crate::security::http::HttpRequest {
                        method: "POST".into(),
                        url: format!("{origin}/"),
                        headers: Default::default(),
                        body: crate::security::http::Body::Absent {},
                        nonce: None,
                    },
                )?;
                if key.state != "active"
                    || key.role != catalog::KeyRole::Root
                    || target.origin() != origin
                    || challenge.len() != 32
                    || !challenge
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(invalid());
                }
                Resolved::RegistrationChallenge {
                    key: Box::new(key),
                    origin,
                    challenge,
                }
            }
            Change::Grant { change } => Resolved::Grant {
                effect: grants::resolve(&tx, &root, change, self.boot_epoch, now)?,
            },
            Change::Catalog { change } => Resolved::Catalog {
                effect: Box::new(catalog::resolve(&tx, &root, change)?),
            },
            Change::ReissueDocument {
                root_key_id,
                add,
                remove,
            } => {
                let reissue = catalog::reissue(&tx, &root, &root_key_id, &add, &remove)?;
                Resolved::ReissueDocument {
                    root: Box::new(reissue.root),
                    add,
                    remove,
                    unsigned: reissue.unsigned,
                }
            }
            Change::IssueDeviceKeys { root_key_id } => {
                let issue = catalog::issue_plan(&tx, &root, &root_key_id)?;
                Resolved::IssueDeviceKeys {
                    root: Box::new(issue.root),
                    sign: issue.sign,
                    agreement: issue.agreement,
                }
            }
            Change::ProvisionIdentity {
                vault_id,
                host,
                port,
                path_segments,
                device_id,
                principal_uid,
                policies,
                grants,
                expiry_days,
                max_uses,
            } => provision_effect(
                &tx,
                now,
                vault_id,
                host,
                port,
                path_segments,
                device_id,
                principal_uid,
                policies,
                grants,
                expiry_days,
                max_uses,
            )?,
            Change::RegisterPrincipal { uid } => {
                if uid == 0 || uid == u32::MAX || tx.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE uid=?1 AND state='enabled')", [uid], |r| r.get::<_,bool>(0)).map_err(db_error)? { return Err(invalid()); }
                let generation: u32 = tx
                    .query_row(
                        "SELECT COALESCE(MAX(generation),0)+1 FROM principals WHERE uid=?1",
                        [uid],
                        |r| r.get(0),
                    )
                    .map_err(db_error)?;
                Resolved::RegisterPrincipal {
                    uid,
                    principal_id: uuid(),
                    generation,
                }
            }
            Change::DisablePrincipal { principal_id } => {
                if !tx.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=?1 AND state='enabled')", [&principal_id], |r| r.get::<_,bool>(0)).map_err(db_error)? { return Err(invalid()); }
                Resolved::DisablePrincipal { principal_id }
            }
            Change::RetireIdentity { did } => {
                let rows: Vec<(String, String)> = {
                    let mut statement = tx
                        .prepare("SELECT vault_id,state FROM keys WHERE did=?1")
                        .map_err(db_error)?;
                    let rows = statement
                        .query_map([&did], |r| Ok((r.get(0)?, r.get(1)?)))
                        .map_err(db_error)?
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(db_error)?;
                    rows
                };
                let vaults: BTreeSet<&str> = rows.iter().map(|(v, _)| v.as_str()).collect();
                // Unknown DID, keys spread across vaults, or nothing left to do.
                if rows.is_empty()
                    || vaults.len() != 1
                    || rows.iter().all(|(_, state)| state == "retired")
                {
                    return Err(invalid());
                }
                let vault_id = vaults
                    .into_iter()
                    .next()
                    .ok_or_else(invalid)?
                    .to_string();
                let layout =
                    crate::keystore::layout::KeydLayout::at(root.join("vaults").join(&vault_id));
                // A published identity is retired through deactivate/migrate;
                // dropping its keys would silently orphan its document.
                if layout.did_path(&did).exists() {
                    return Err(invalid());
                }
                let pending: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM file_operations WHERE vault_id=?1 AND did=?2 AND state='pending')",
                        params![vault_id, did],
                        |r| r.get(0),
                    )
                    .map_err(db_error)?;
                if pending {
                    return Err(invalid());
                }
                Resolved::RetireIdentity { did, vault_id }
            }
            Change::RefreshGrants { principal_id, did } => {
                if !tx.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=?1 AND state='enabled')", [&principal_id], |r| r.get::<_,bool>(0)).map_err(db_error)? { return Err(invalid()); }
                let rows: Vec<(String, String, String, u32, i64, i64, u32, String)> = {
                    let mut statement = tx
                        .prepare(
                            "SELECT g.grant_id,g.key_id,g.policy_id,g.policy_version,g.created_at,g.expiry,g.max_uses,g.kind \
                             FROM grants g JOIN keys k ON k.key_id=g.key_id \
                             WHERE g.principal_id=?1 AND k.did=?2 \
                               AND g.state IN ('revoked_restart','expired','exhausted') \
                             ORDER BY g.created_at DESC, g.grant_id DESC",
                        )
                        .map_err(db_error)?;
                    let rows = statement
                        .query_map(params![principal_id, did], |r| {
                            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))
                        })
                        .map_err(db_error)?
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(db_error)?;
                    rows
                };
                let mut seen = BTreeSet::new();
                let mut replaced = BTreeSet::new();
                let mut effects = Vec::new();
                let mut superseded = Vec::new();
                for (grant_id, key_id, policy_id, policy_version, created_at, expiry, max_uses, kind) in rows {
                    let tuple = (
                        key_id.clone(),
                        policy_id.clone(),
                        policy_version,
                        kind.clone(),
                    );
                    // One replacement per key/policy/kind: an identity that has
                    // been refreshed before carries older rows for the same
                    // authorization.
                    if !seen.insert(tuple.clone()) {
                        if replaced.contains(&tuple) {
                            superseded.push(grant_id);
                        }
                        continue;
                    }
                    // Only reissue when the authorization has no live grant of
                    // its own; a stale lost row must not pile up a duplicate.
                    let live: bool = tx
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM grants \
                             WHERE principal_id=?1 AND key_id=?2 AND policy_id=?3 \
                               AND policy_version=?4 AND kind=?5 AND state='active')",
                            params![principal_id, key_id, policy_id, policy_version, kind],
                            |r| r.get(0),
                        )
                        .map_err(db_error)?;
                    if live {
                        continue;
                    }
                    let Some(lifetime) = expiry.checked_sub(created_at).filter(|v| *v > 0) else {
                        continue;
                    };
                    let new_expiry = now.wall.checked_add(lifetime).ok_or_else(invalid)?;
                    let change = |kind: &str| {
                        let (key_id, policy_id) = (key_id.clone(), policy_id.clone());
                        if kind == "session" {
                            grants::GrantChange::CreateSession {
                                principal_id: principal_id.clone(),
                                key_id,
                                policy_id,
                                policy_version,
                                expiry: new_expiry,
                                max_uses,
                            }
                        } else {
                            grants::GrantChange::Create {
                                principal_id: principal_id.clone(),
                                key_id,
                                policy_id,
                                policy_version,
                                expiry: new_expiry,
                                max_uses,
                            }
                        }
                    };
                    effects.push(
                        grants::resolve(&tx, &root, change(&kind), self.boot_epoch, now)
                            .map_err(|_| invalid())?,
                    );
                    replaced.insert(tuple);
                    superseded.push(grant_id);
                }
                if effects.is_empty() {
                    return Err(invalid());
                }
                Resolved::RefreshGrants { did, effects, superseded }
            }
        };
        let epoch: i64 = tx
            .query_row(
                "SELECT mutation_epoch FROM service_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        let operation_id = uuid();
        let effect = serde_json::to_value(&resolved).map_err(|_| invalid())?;
        let payload = serde_json::to_string(&resolved).map_err(|_| invalid())?;
        let expires_at = now.wall.checked_add(120).ok_or_else(invalid)?;
        let monotonic_deadline = now.monotonic_ms.checked_add(120_000).ok_or_else(invalid)?;
        let binding = json!({"operation_id":operation_id,"actor":actor,"boot_epoch":self.boot_epoch,"epoch":epoch,"expires_at":expires_at,"monotonic_deadline":monotonic_deadline,"effect":effect});
        let digest = hex(&Sha256::digest(
            serde_json_canonicalizer::to_vec(&binding).map_err(|_| invalid())?,
        ));
        tx.execute(
            "INSERT INTO admin_operations VALUES(?1,?2,'management',?3,?4,?5,?6,?7,?8,'prepared')",
            params![
                operation_id,
                actor,
                payload,
                digest,
                epoch,
                self.boot_epoch,
                expires_at,
                monotonic_deadline
            ],
        )
        .map_err(db_error)?;
        append(
            &tx,
            &json!({"event":"OPERATION_PREPARED","actor":actor,"operation_id":operation_id,"digest":digest}),
        )?;
        tx.commit().map_err(db_error)?;
        Ok(Prepared {
            operation_id,
            digest,
            effect,
            expires_at,
        })
    }

    pub fn mutation_epoch(&self) -> Result<i64> {
        self.connection
            .query_row(
                "SELECT mutation_epoch FROM service_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(db_error)
    }
    pub fn commit_changes_keys(&self, operation_id: &str) -> Result<bool> {
        let payload: Option<String> = self
            .connection
            .query_row(
                "SELECT payload FROM admin_operations WHERE operation_id=?1",
                [operation_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        Ok(match payload {
            Some(p) => match serde_json::from_str::<Resolved>(&p).map_err(|_| unavailable())? {
                // The first document of a just-provisioned vault: these are the
                // keys the same passphrase unlocked seconds ago, and the grants
                // came from the same operation (their document digest is still
                // the genesis sentinel, so the revocation step skips them).
                // Locking here would turn "one confirmation" into "one
                // confirmation plus one unlock", so only this first install
                // keeps the keys available.
                Resolved::Catalog { effect } => match *effect {
                    catalog::CatalogEffect::InstallDocument {
                        before_digest, ..
                    } => before_digest != GENESIS,
                    _ => true,
                },
                Resolved::RotateHotKey { .. }
                | Resolved::ReissueDocument { .. }
                | Resolved::IssueDeviceKeys { .. } => true,
                _ => false,
            },
            None => false,
        })
    }

    pub fn commit(
        &mut self,
        actor: u32,
        operation_id: &str,
        digest: &str,
        now: Time,
    ) -> Result<()> {
        self.commit_intent(actor, operation_id, digest, now)?;
        catalog::recover_files(&mut self.connection, &self.root)
    }

    fn commit_intent(
        &mut self,
        actor: u32,
        operation_id: &str,
        digest: &str,
        now: Time,
    ) -> Result<()> {
        self.commit_secret(actor, operation_id, digest, now, None)
            .map(|_| ())
    }

    /// One-shot registration. Root is decrypted transiently, never installed in
    /// the data-plane vault. Return only after the operation and audit commit.
    pub fn complete_secret_operation(
        &mut self,
        actor: u32,
        operation_id: &str,
        digest: &str,
        now: Time,
        secret: &str,
    ) -> Result<Value> {
        let result = self
            .commit_secret(actor, operation_id, digest, now, Some(secret))?
            .ok_or_else(invalid)?;
        catalog::recover_files(&mut self.connection, &self.root)?;
        Ok(result)
    }

    fn commit_secret(
        &mut self,
        actor: u32,
        operation_id: &str,
        digest: &str,
        now: Time,
        secret: Option<&str>,
    ) -> Result<Option<Value>> {
        let started = std::time::Instant::now();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let operation: Option<(String,i64,i64,i64)> = tx.query_row("SELECT payload,identity_epoch,expires_at,monotonic_deadline FROM admin_operations WHERE operation_id=?1 AND actor=?2 AND digest=?3 AND boot_epoch=?4 AND state='prepared' AND expires_at>?5 AND monotonic_deadline>?6 AND identity_epoch=(SELECT mutation_epoch FROM service_meta WHERE singleton=1)", params![operation_id,actor,digest,self.boot_epoch,now.wall,now.monotonic_ms], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(db_error)?;
        let (payload, epoch, expires_at, monotonic_deadline) = operation.ok_or_else(invalid)?;
        let resolved: Resolved = serde_json::from_str(&payload).map_err(|_| unavailable())?;
        let binding = json!({"operation_id":operation_id,"actor":actor,"boot_epoch":self.boot_epoch,"epoch":epoch,"expires_at":expires_at,"monotonic_deadline":monotonic_deadline,"effect":serde_json::to_value(&resolved).map_err(|_| unavailable())?});
        let actual = hex(&Sha256::digest(
            serde_json_canonicalizer::to_vec(&binding).map_err(|_| unavailable())?,
        ));
        if actual != digest {
            return Err(invalid());
        }
        let mut result = None;
        // Files a credential-bearing mint wrote are removed unless the commit
        // lands; declared here so the guard outlives the match arm.
        let mut minted: Option<MintedFiles> = None;
        // A credential-bearing commit cannot be used for unrelated operations.
        if secret.is_some()
            != matches!(
                &resolved,
                Resolved::RegistrationChallenge { .. }
                    | Resolved::RotateHotKey { .. }
                    | Resolved::ReissueDocument { .. }
                    | Resolved::IssueDeviceKeys { .. }
                    | Resolved::ProvisionIdentity { .. }
            )
        {
            return Err(invalid());
        }
        match resolved {
            Resolved::RotateHotKey {
                root,
                old,
                next,
                unsigned,
            } => {
                for key in [&root, &old, &next] {
                    if catalog::get_key(&tx, &key.key_id)? != **key {
                        return Err(invalid());
                    }
                    catalog::validate_key(&self.root, key)?;
                }
                let layout = crate::keystore::layout::KeydLayout::at(
                    self.root.join("vaults").join(&root.vault_id),
                );
                let fragment = root
                    .kid
                    .strip_prefix(&format!("{}#", root.did))
                    .ok_or_else(invalid)?;
                let wrapped = crate::keystore::store::resolve(&layout, &root.did, Some(fragment))?;
                let signer = crate::keystore::unwrap::unlock(
                    &wrapped,
                    secret.ok_or_else(invalid)?.as_bytes(),
                    &crate::keystore::device::load(&layout)?,
                )?;
                let document = crate::did::document::sign_document(&unsigned, &signer, &root.kid)?;
                let effect = catalog::resolve(
                    &tx,
                    &self.root,
                    catalog::CatalogChange::InstallDocument {
                        vault_id: root.vault_id.clone(),
                        document: document.clone(),
                    },
                )?;
                catalog::apply(&tx, &self.root, operation_id, effect)?;
                result = Some(
                    json!({"document":document,"retired_key_id":old.key_id,"next_key_id":next.key_id,"publication_required":true}),
                );
            }
            Resolved::ReissueDocument {
                root,
                add,
                remove,
                unsigned,
            } => {
                if catalog::get_key(&tx, &root.key_id)? != *root {
                    return Err(invalid());
                }
                // Between approval and completion the document or an envelope
                // can move. Recompute from the same inputs; only an unsigned
                // document that comes out byte-identical to the approved one
                // may be signed.
                let fresh = catalog::reissue(&tx, &self.root, &root.key_id, &add, &remove)?;
                if fresh.unsigned != unsigned {
                    return Err(invalid());
                }
                let layout = crate::keystore::layout::KeydLayout::at(
                    self.root.join("vaults").join(&root.vault_id),
                );
                let fragment = root
                    .kid
                    .strip_prefix(&format!("{}#", root.did))
                    .ok_or_else(invalid)?;
                let wrapped = crate::keystore::store::resolve(&layout, &root.did, Some(fragment))?;
                let signer = crate::keystore::unwrap::unlock(
                    &wrapped,
                    secret.ok_or_else(invalid)?.as_bytes(),
                    &crate::keystore::device::load(&layout)?,
                )?;
                let document = crate::did::document::sign_document(&unsigned, &signer, &root.kid)?;
                let effect = catalog::resolve(
                    &tx,
                    &self.root,
                    catalog::CatalogChange::InstallDocument {
                        vault_id: root.vault_id.clone(),
                        document: document.clone(),
                    },
                )
                .map_err(|_| invalid())?;
                catalog::apply(&tx, &self.root, operation_id, effect)?;
                result = Some(json!({
                    "document": document,
                    "added": add.iter().map(|addition| addition.kid.clone()).collect::<Vec<_>>(),
                    "removed": remove,
                    "publication_required": true,
                }));
            }
            Resolved::IssueDeviceKeys {
                root,
                sign,
                agreement,
            } => {
                if catalog::get_key(&tx, &root.key_id)? != *root {
                    return Err(invalid());
                }
                // 名字在批准时定下了,这里只认那一对。中间有人刚铸过同名的一
                // 对时,重算出来的名字会往后挪 —— 于是这条批准作废,而不是铸
                // 一对名字和批准的不一样的钥匙。
                let plan = catalog::issue_plan(&tx, &self.root, &root.key_id)?;
                if plan.sign != sign || plan.agreement != agreement {
                    return Err(invalid());
                }
                let layout = crate::keystore::layout::KeydLayout::at(
                    self.root.join("vaults").join(&root.vault_id),
                );
                let fragment = root
                    .kid
                    .strip_prefix(&format!("{}#", root.did))
                    .ok_or_else(invalid)?;
                let wrapped = crate::keystore::store::resolve(&layout, &root.did, Some(fragment))?;
                let secret = secret.ok_or_else(invalid)?;
                // 先解开根,再铸:口令错了不该留下半套信封。
                crate::keystore::unwrap::unlock(
                    &wrapped,
                    secret.as_bytes(),
                    &crate::keystore::device::load(&layout)?,
                )
                .map_err(|_| invalid())?;
                let device_secret = crate::keystore::device::load(&layout)?;
                // 两把都先算出来,再一起落盘:硬件根不可用这类失败因此什么都
                // 不留,而不是留下"签名键进去了、协商键没有"的半套设备。
                let (sign_wrapped, _) = crate::keystore::create::generate_extra(
                    &root.did,
                    &sign,
                    vec![
                        anp::authentication::DidVerificationRelationship::Authentication,
                        anp::authentication::DidVerificationRelationship::AssertionMethod,
                    ],
                    "device-sign",
                    secret.as_bytes(),
                    &device_secret,
                    crate::crypto::kdf::Argon2Config::default(),
                    crate::keystore::hardware::HardwareChoice::None,
                )
                .map_err(|_| invalid())?;
                let (agreement_wrapped, _) = crate::keystore::create::generate_agreement(
                    &root.did,
                    &agreement,
                    "device-agreement",
                    secret.as_bytes(),
                    &device_secret,
                    crate::crypto::kdf::Argon2Config::default(),
                    crate::keystore::hardware::HardwareChoice::None,
                )
                .map_err(|_| invalid())?;
                for issued in [&sign_wrapped, &agreement_wrapped] {
                    crate::keystore::store::save_new(&layout, issued).map_err(|_| invalid())?;
                }
                let issued: Vec<Value> = [&sign_wrapped, &agreement_wrapped]
                    .iter()
                    .map(|envelope| {
                        json!({
                            "kid": envelope.id.kid,
                            "algorithm": envelope.algorithm,
                            "public_multibase": envelope.public_multibase,
                        })
                    })
                    .collect();
                result = Some(json!({
                    "keys": issued,
                    "next": "reissue_document",
                }));
            }
            Resolved::ProvisionIdentity {
                vault_id,
                host,
                port,
                path_segments,
                device_id,
                principal_id,
                policies,
                grants,
                expiry,
                max_uses,
            } => {
                let secret = secret.ok_or_else(invalid)?;
                let layout = crate::keystore::layout::KeydLayout::at(
                    self.root.join("vaults").join(&vault_id),
                );
                layout.ensure().map_err(|_| invalid())?;
                let device_secret = crate::keystore::device::load_or_create(&layout)?;
                let mut spec = crate::did::spec::DidDocumentSpec::new(&host, path_segments);
                if let Some(port) = port {
                    spec = spec.with_port(port);
                }
                // 三把都由这一份口令封起来。全部算完才落盘,写盘之后由
                // `MintedFiles` 兜底:事务没提交就删干净。
                let created = crate::keystore::create::generate(
                    &spec,
                    "identity",
                    secret.as_bytes(),
                    &device_secret,
                    crate::crypto::kdf::Argon2Config::default(),
                    crate::keystore::hardware::HardwareChoice::None,
                )?;
                let did = created.did.clone();
                let (sign_wrapped, _) = crate::keystore::create::generate_extra(
                    &did,
                    &format!("{device_id}-sign"),
                    vec![
                        anp::authentication::DidVerificationRelationship::Authentication,
                        anp::authentication::DidVerificationRelationship::AssertionMethod,
                    ],
                    "device-sign",
                    secret.as_bytes(),
                    &device_secret,
                    crate::crypto::kdf::Argon2Config::default(),
                    crate::keystore::hardware::HardwareChoice::None,
                )?;
                let (agreement_wrapped, _) = crate::keystore::create::generate_agreement(
                    &did,
                    &format!("{device_id}-agreement"),
                    "device-agreement",
                    secret.as_bytes(),
                    &device_secret,
                    crate::crypto::kdf::Argon2Config::default(),
                    crate::keystore::hardware::HardwareChoice::None,
                )?;

                let mut files = MintedFiles::default();
                for wrapped in [&created.wrapped, &sign_wrapped, &agreement_wrapped] {
                    let path = layout.key_path(&wrapped.id.thumbprint)?;
                    crate::keystore::store::save_new(&layout, wrapped)?;
                    files.push(path);
                }
                // 批准到完成之间这个 DID 可能已经进了目录或落了文档。有一处
                // 就作废 —— 刚写的信封随 `files` 一起删掉。
                let known: bool = tx
                    .query_row("SELECT EXISTS(SELECT 1 FROM keys WHERE did=?1)", [&did], |r| {
                        r.get::<_, bool>(0)
                    })
                    .map_err(db_error)?;
                if known || layout.did_path(&did).exists() {
                    return Err(invalid());
                }

                let records = vec![
                    provision_record(&vault_id, &did, &created.wrapped, catalog::KeyRole::Root, "")?,
                    provision_record(
                        &vault_id,
                        &did,
                        &sign_wrapped,
                        catalog::KeyRole::DeviceSigning,
                        "device_assertion",
                    )?,
                    provision_record(
                        &vault_id,
                        &did,
                        &agreement_wrapped,
                        catalog::KeyRole::KeyAgreement,
                        "",
                    )?,
                ];
                let effect = catalog::resolve(
                    &tx,
                    &self.root,
                    catalog::CatalogChange::AddKeys {
                        vault_id: vault_id.clone(),
                        did: did.clone(),
                        keys: records.clone(),
                    },
                )?;
                catalog::apply(&tx, &self.root, operation_id, effect)?;
                for policy in &policies {
                    let effect = catalog::resolve(
                        &tx,
                        &self.root,
                        catalog::CatalogChange::PublishPolicy {
                            policy_id: policy.policy_id.clone(),
                            version: 1,
                            content: policy.content.clone(),
                        },
                    )?;
                    catalog::apply(&tx, &self.root, operation_id, effect)?;
                }

                let mut reply_grants = serde_json::Map::new();
                for grant in &grants {
                    let key = records
                        .iter()
                        .find(|record| record.role == grant.key)
                        .ok_or_else(invalid)?;
                    let effect = grants::resolve(
                        &tx,
                        &self.root,
                        grants::GrantChange::Create {
                            principal_id: principal_id.clone(),
                            key_id: key.key_id.clone(),
                            policy_id: grant.policy_id.clone(),
                            policy_version: 1,
                            expiry,
                            max_uses,
                        },
                        self.boot_epoch,
                        now,
                    )?;
                    let grant_id = match &effect {
                        grants::Effect::Create { grant, .. } => grant.grant_id.clone(),
                        grants::Effect::Revoke { .. } => return Err(invalid()),
                    };
                    grants::apply(&tx, &self.root, effect, self.boot_epoch, now)?;
                    reply_grants.insert(
                        grant.grant_name.clone(),
                        json!({"grant_id": grant_id, "key_id": key.key_id}),
                    );
                }
                let reply_keys: Vec<Value> = records
                    .iter()
                    .zip([&created.wrapped, &sign_wrapped, &agreement_wrapped])
                    .map(|(record, wrapped)| {
                        json!({
                            "key_id": record.key_id,
                            "role": record.role,
                            "kid": record.kid,
                            "public_multibase": wrapped.public_multibase,
                        })
                    })
                    .collect();
                result = Some(json!({
                    "vault_id": vault_id,
                    "did": did,
                    "device_id": device_id,
                    "keys": reply_keys,
                    "grants": reply_grants,
                }));
                minted = Some(files);
            }
            Resolved::RegistrationChallenge {
                key,
                origin,
                challenge,
            } => {
                use crate::sign::Signer;
                use base64::Engine;
                if catalog::get_key(&tx, &key.key_id)? != *key {
                    return Err(invalid());
                }
                catalog::validate_key(&self.root, &key)?;
                let layout = crate::keystore::layout::KeydLayout::at(
                    self.root.join("vaults").join(&key.vault_id),
                );
                let fragment = key
                    .kid
                    .strip_prefix(&format!("{}#", key.did))
                    .ok_or_else(invalid)?;
                let wrapped = crate::keystore::store::resolve(&layout, &key.did, Some(fragment))?;
                let signer = crate::keystore::unwrap::unlock(
                    &wrapped,
                    secret.ok_or_else(invalid)?.as_bytes(),
                    &crate::keystore::device::load(&layout)?,
                )?;
                let signature = signer.sign(challenge.as_bytes())?;
                result = Some(
                    json!({"kid":key.kid,"origin":origin,"challenge_signature":base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)}),
                );
            }
            Resolved::Grant { effect } => {
                grants::apply(&tx, &self.root, effect, self.boot_epoch, now)?
            }
            Resolved::Catalog { effect } => catalog::apply(&tx, &self.root, operation_id, *effect)?,
            Resolved::RegisterPrincipal {
                uid,
                principal_id,
                generation,
            } => {
                tx.execute(
                    "INSERT INTO principals VALUES(?1,?2,?3,'enabled',?4)",
                    params![principal_id, uid, generation, now.wall],
                )
                .map_err(db_error)?;
            }
            Resolved::DisablePrincipal { principal_id } => {
                if tx.execute("UPDATE principals SET state='disabled' WHERE principal_id=?1 AND state='enabled'", [&principal_id]).map_err(db_error)? != 1 { return Err(invalid()); }
                tx.execute(
                    "UPDATE grants SET state='revoked' WHERE principal_id=?1 AND state='active'",
                    [&principal_id],
                )
                .map_err(db_error)?;
            }
            Resolved::RetireIdentity { did, vault_id } => {
                // Re-check: installing a document between prepare and commit
                // would make retiring the keys destroy a live identity.
                let layout = crate::keystore::layout::KeydLayout::at(
                    self.root.join("vaults").join(&vault_id),
                );
                if layout.did_path(&did).exists() {
                    return Err(invalid());
                }
                let retired = tx
                    .execute(
                        "UPDATE keys SET state='retired' WHERE vault_id=?1 AND did=?2 AND state!='retired'",
                        params![vault_id, did],
                    )
                    .map_err(db_error)?;
                if retired == 0 {
                    return Err(invalid());
                }
                let revoked = tx
                    .execute(
                        "UPDATE grants SET state='revoked' WHERE state='active' AND key_id IN \
                         (SELECT key_id FROM keys WHERE vault_id=?1 AND did=?2)",
                        params![vault_id, did],
                    )
                    .map_err(db_error)?;
                result = Some(json!({
                    "vault_id": vault_id,
                    "did": did,
                    "retired_keys": retired,
                    "revoked_grants": revoked,
                }));
            }
            Resolved::RefreshGrants { did, effects, superseded } => {
                for grant_id in superseded {
                    if tx
                        .execute(
                            "UPDATE grants SET state='revoked' WHERE grant_id=?1 \
                             AND state IN ('revoked_restart','expired','exhausted')",
                            [&grant_id],
                        )
                        .map_err(db_error)?
                        != 1
                    {
                        return Err(invalid());
                    }
                }
                let mut issued = Vec::new();
                for effect in effects {
                    let info = match &effect {
                        grants::Effect::Create { grant, .. } => json!({
                            "grant_id": grant.grant_id,
                            "key_id": grant.key_id,
                            "policy_id": grant.policy_id,
                            "policy_version": grant.policy_version,
                            "kind": grant.kind,
                            "expiry": grant.expiry,
                            "max_uses": grant.max_uses,
                        }),
                        grants::Effect::Revoke { .. } => return Err(invalid()),
                    };
                    grants::apply(&tx, &self.root, effect, self.boot_epoch, now)?;
                    issued.push(info);
                }
                result = Some(json!({"did": did, "grants": issued}));
            }
        }
        let elapsed_ms = i64::try_from(started.elapsed().as_millis()).map_err(|_| invalid())?;
        if now.monotonic_ms.saturating_add(elapsed_ms) >= monotonic_deadline
            || now.wall.saturating_add(elapsed_ms / 1000) >= expires_at
        {
            return Err(invalid());
        }
        tx.execute(
            "UPDATE service_meta SET mutation_epoch=mutation_epoch+1 WHERE singleton=1",
            [],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE admin_operations SET state='committed' WHERE operation_id=?1",
            [operation_id],
        )
        .map_err(db_error)?;
        append(
            &tx,
            &json!({"event":"OPERATION_COMMITTED","actor":actor,"operation_id":operation_id,"digest":digest}),
        )?;
        tx.commit().map_err(db_error)?;
        // 目录行已经落库,信封从此归 catalog 所有。
        if let Some(files) = minted.take() {
            files.keep();
        }
        Ok(result)
    }

    pub fn catalog(&self) -> Result<catalog::Catalog> {
        catalog::list(&self.connection)
    }

    pub fn check_key(&self, vault: &str, did: &str, kid: &str) -> Result<()> {
        catalog::check_key(&self.connection, &self.root, vault, did, kid)
    }

    pub fn record(&mut self, event: Value) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        append(&tx, &event)?;
        tx.commit().map_err(db_error)
    }

    /// Session loss never refunds quotas, restores grants, or deletes results.
    /// Invalidate prepared approvals as well, so an old approval cannot recreate
    /// authority after a fresh login/unlock.
    pub(crate) fn end_se_session(&mut self, actor: u32, session_id: &str) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        tx.execute(
            "UPDATE grants SET state='revoked' WHERE state IN ('active','exhausted')",
            [],
        )
        .map_err(db_error)?;
        // Every prepared approval is pinned to this epoch. Advancing it expires
        // those approvals without changing the existing on-disk schema/states.
        tx.execute(
            "UPDATE service_meta SET mutation_epoch=mutation_epoch+1 WHERE singleton=1",
            [],
        )
        .map_err(db_error)?;
        append(
            &tx,
            &json!({"event":"SE_SESSION_ENDED","actor":actor,"session_id":session_id}),
        )?;
        tx.commit().map_err(db_error)
    }
}

fn managed_marker(root: &Path, instance: &str) -> Result<()> {
    let path = root.join(".anpio-key-managed");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(instance.as_bytes())?;
            file.sync_all()?;
            std::fs::File::open(root)?.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(&path)?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.uid() != std::fs::metadata(root)?.uid()
                || meta.mode() & 0o777 != 0o600
                || std::fs::read_to_string(&path)? != instance
            {
                return Err(unavailable());
            }
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn unconfigured(path: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(db_error)
}
fn open_new(path: &Path) -> Result<Connection> {
    let connection = unconfigured(path)?;
    settings(&connection)?;
    Ok(connection)
}
fn open(path: &Path) -> Result<Connection> {
    let connection = unconfigured(path)?;
    // Do not change journal settings of a newer or unrelated database.
    let version: i64 = connection
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(db_error)?;
    let app: i64 = connection
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(db_error)?;
    if !(1..=SCHEMA).contains(&version) || app != APPLICATION {
        return Err(unavailable());
    }
    settings(&connection)?;
    Ok(connection)
}
fn audit_hash(seq: i64, prev: &str, data: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"anp-keyd/sqlite-audit/v1\0");
    hash.update(seq.to_be_bytes());
    hash.update(prev.as_bytes());
    hash.update(data);
    hex(&hash.finalize())
}
fn append(tx: &Transaction<'_>, event: &Value) -> Result<()> {
    let (last, prev): (i64, String) = tx
        .query_row(
            "SELECT seq,event_digest FROM audit_events ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(db_error)?
        .unwrap_or((0, GENESIS.into()));
    let seq = last.checked_add(1).ok_or_else(unavailable)?;
    let data = serde_json_canonicalizer::to_vec(event).map_err(|_| unavailable())?;
    tx.execute(
        "INSERT INTO audit_events VALUES(?1,?2,?3,?4)",
        params![seq, prev, audit_hash(seq, &prev, &data), data],
    )
    .map_err(db_error)?;
    Ok(())
}
fn verify_audit(connection: &Connection) -> Result<()> {
    let mut statement = connection
        .prepare("SELECT seq,prev,event_digest,event_data FROM audit_events ORDER BY seq")
        .map_err(db_error)?;
    let mut rows = statement.query([]).map_err(db_error)?;
    let mut seq = 0;
    let mut tail = GENESIS.to_string();
    while let Some(row) = rows.next().map_err(db_error)? {
        let next: i64 = row.get(0).map_err(db_error)?;
        let prev: String = row.get(1).map_err(db_error)?;
        let digest: String = row.get(2).map_err(db_error)?;
        let data: Vec<u8> = row.get(3).map_err(db_error)?;
        if next != seq + 1 || prev != tail || digest != audit_hash(next, &prev, &data) {
            return Err(unavailable());
        }
        seq = next;
        tail = digest;
    }
    if seq == 0 {
        return Err(unavailable());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn local_filesystem(path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| unavailable())?;
    let mut stat = std::mem::MaybeUninit::<nix::libc::statfs>::uninit();
    // statfs initializes the entire structure on success; path is NUL terminated.
    if unsafe { nix::libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(unavailable());
    }
    let kind = unsafe { stat.assume_init() }.f_type as u64;
    // ext2/3/4, XFS, Btrfs, tmpfs and overlayfs only. NFS/CIFS/FUSE/unknown fail closed.
    if ![0xef53, 0x58465342, 0x9123683e, 0x01021994, 0x794c7630].contains(&kind) {
        return Err(unavailable());
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn local_filesystem(path: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| unavailable())?;
    let mut stat = std::mem::MaybeUninit::<nix::libc::statfs>::uninit();
    // A successful statfs initializes the structure. Only local APFS is accepted.
    if unsafe { nix::libc::statfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(unavailable());
    }
    let stat = unsafe { stat.assume_init() };
    let kind = unsafe { std::ffi::CStr::from_ptr(stat.f_fstypename.as_ptr()) };
    if kind.to_bytes() != b"apfs" || stat.f_flags & nix::libc::MNT_LOCAL as u32 == 0 {
        return Err(unavailable());
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn local_filesystem(_: &Path) -> Result<()> {
    crate::security::require_boundary_platform()
}

#[cfg(test)]
mod tests;
