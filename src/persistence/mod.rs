//! Single-writer state and transactional audit. Never stores private material.
pub mod catalog;
pub mod checkpoint;
pub mod clock;
pub mod grants;
mod policy;
pub mod projection;
pub mod requests;

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

const SCHEMA: i64 = 3;
const APPLICATION: i64 = 0x414e504b;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Change {
    /// Switch to a pre-provisioned hot key and retire the old public method.
    RotateHotKey {
        root_key_id: String,
        old_key_id: String,
        next_key_id: String,
    },
    /// Exact awiki registration proof, authorized only through management.
    RegistrationChallenge {
        key_id: String,
        origin: String,
        challenge: String,
    },
    RegisterPrincipal {
        uid: u32,
    },
    DisablePrincipal {
        principal_id: String,
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
            Some(p) => matches!(
                serde_json::from_str::<Resolved>(&p).map_err(|_| unavailable())?,
                Resolved::Catalog { .. } | Resolved::RotateHotKey { .. }
            ),
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
        // A credential-bearing commit cannot be used for unrelated operations.
        if secret.is_some()
            != matches!(
                &resolved,
                Resolved::RegistrationChallenge { .. } | Resolved::RotateHotKey { .. }
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
        let tx = self.connection.transaction_with_behavior(TransactionBehavior::Immediate).map_err(db_error)?;
        tx.execute("UPDATE grants SET state='revoked' WHERE state IN ('active','exhausted')", []).map_err(db_error)?;
        // Every prepared approval is pinned to this epoch. Advancing it expires
        // those approvals without changing the existing on-disk schema/states.
        tx.execute("UPDATE service_meta SET mutation_epoch=mutation_epoch+1 WHERE singleton=1", []).map_err(db_error)?;
        append(&tx, &json!({"event":"SE_SESSION_ENDED","actor":actor,"session_id":session_id}))?;
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
