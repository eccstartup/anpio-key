//! Trusted catalog management. Paths and digests are derived inside the service.
use super::*;
use crate::keystore::{
    layout::KeydLayout,
    record::{KeyAlgorithm, WrappedKey},
    store,
};
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    Unclassified,
    Root,
    Hot,
    Recovery,
    Challenge,
    DeviceSigning,
    KeyAgreement,
}
impl KeyRole {
    fn name(&self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::Root => "root",
            Self::Hot => "hot",
            Self::Recovery => "recovery",
            Self::Challenge => "challenge",
            Self::DeviceSigning => "device_signing",
            Self::KeyAgreement => "key_agreement",
        }
    }
}
/// A device signing key is bound to exactly one purpose when it is classified;
/// every other role carries none.
pub(super) fn purpose_valid(role: &KeyRole, purpose: &str) -> bool {
    match role {
        KeyRole::DeviceSigning => matches!(purpose, "device_assertion" | "application_assertion"),
        _ => purpose.is_empty(),
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub enum CatalogChange {
    EnrollVault {
        vault_id: String,
    },
    ConfirmRole {
        key_id: String,
        role: KeyRole,
        /// Present only for `device_signing`; omitted or empty otherwise.
        #[serde(default)]
        purpose: String,
    },
    PublishPolicy {
        policy_id: String,
        version: u32,
        content: Value,
    },
    InstallDocument {
        vault_id: String,
        document: Value,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    pub key_id: String,
    pub vault_id: String,
    pub did: String,
    pub kid: String,
    pub role: KeyRole,
    /// Non-empty only for `device_signing`; the purpose the key was bound to
    /// when it was classified.
    #[serde(default)]
    pub purpose: String,
    pub envelope_digest: String,
    pub document_digest: String,
    pub state: String,
    pub identity_epoch: i64,
    pub generation: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub vaults: Vec<Value>,
    pub keys: Vec<KeyRecord>,
    pub policies: Vec<Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub enum CatalogEffect {
    EnrollVault {
        vault_id: String,
        keys: Vec<KeyRecord>,
        #[serde(default)]
        legacy_audit: Option<Value>,
    },
    ConfirmRole {
        before: Box<KeyRecord>,
        after: Box<KeyRecord>,
    },
    PublishPolicy {
        policy_id: String,
        version: u32,
        content: String,
        digest: String,
    },
    InstallDocument {
        vault_id: String,
        did: String,
        before_digest: String,
        document: Value,
        after_digest: String,
    },
}
fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex(&Sha256::digest(
        serde_json_canonicalizer::to_vec(value).map_err(|_| invalid())?,
    )))
}
fn layout(root: &Path, vault: &str) -> Result<KeydLayout> {
    if !crate::principal::validate_uuid(vault) {
        return Err(invalid());
    }
    let path = root.join("vaults").join(vault);
    let uid = std::fs::symlink_metadata(root)?.uid();
    for dir in [
        root.join("vaults"),
        path.clone(),
        path.join("keys"),
        path.join("dids"),
    ] {
        let meta = std::fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err(invalid());
        }
    }
    let secret = std::fs::symlink_metadata(path.join("device.secret"))?;
    if !secret.is_file()
        || secret.uid() != uid
        || secret.nlink() != 1
        || secret.mode() & 0o777 != 0o600
    {
        return Err(invalid());
    }
    Ok(KeydLayout::at(path))
}
fn active_vault(tx: &Connection, vault: &str) -> Result<()> {
    let path: Option<String> = tx
        .query_row(
            "SELECT relative_path FROM vaults WHERE vault_id=?1 AND state='active'",
            [vault],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?;
    if path.as_deref() != Some(format!("vaults/{vault}").as_str()) {
        return Err(invalid());
    }
    Ok(())
}
fn document(layout: &KeydLayout, did: &str) -> Result<Value> {
    let path = layout.did_path(did);
    let meta = std::fs::symlink_metadata(&path)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != std::fs::metadata(layout.root())?.uid()
        || meta.mode() & 0o022 != 0
    {
        return Err(invalid());
    }
    let doc = store::read_did_document(layout, did)?;
    crate::did::document::verify_path_binding(did, &doc)?;
    Ok(doc)
}
fn verify_role(wrapped: &WrappedKey, doc: &Value, role: &KeyRole) -> Result<()> {
    if crate::did::lifecycle::is_deactivated(doc) {
        return Err(invalid());
    }
    let method =
        anp::authentication::find_verification_method(doc, &wrapped.id.kid).ok_or_else(invalid)?;
    let material = anp::authentication::extract_public_key(&method).map_err(|_| invalid())?;

    // 指纹按曲线各算一遍,并且**必须**和信封上写着的那一种曲线一起对:
    // 一个 `e1_` 信封配一把 X25519 方法(或反过来)在这里就拒绝,而不是等到
    // 签名时才发现拿错了钥匙。DID 路径段绑的永远是根 Ed25519 键,所以
    // `root` 只有 Ed25519 那一支可能为真。
    let e1 = crate::crypto::thumbprint::e1_segment;
    let (root, fingerprint_matches) = match (wrapped.algorithm, material) {
        (KeyAlgorithm::Ed25519, anp::PublicKeyMaterial::Ed25519(pk)) => (
            crate::daemon::state::thumbprint_of(&wrapped.id.did)? == wrapped.id.thumbprint,
            e1(&pk)? == wrapped.id.thumbprint,
        ),
        (KeyAlgorithm::X25519, anp::PublicKeyMaterial::X25519(pk)) => (
            false,
            crate::crypto::thumbprint::x1_segment(&x25519_dalek::PublicKey::from(pk))
                == wrapped.id.thumbprint,
        ),
        _ => return Err(invalid()),
    };
    if !fingerprint_matches {
        return Err(invalid());
    }

    let authorized = |name: &str| {
        doc.get(name)
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().any(|v| {
                    v.as_str().or_else(|| v.get("id").and_then(Value::as_str))
                        == Some(wrapped.id.kid.as_str())
                })
            })
    };
    // 签名角色只认 Ed25519,协商角色只认 X25519 —— 文档里把一条曲线挂到
    // 另一条的关系下,这里要把那一档整体判死。
    let signs = wrapped.algorithm == KeyAlgorithm::Ed25519;
    let agrees = wrapped.algorithm == KeyAlgorithm::X25519;
    let valid = match role {
        KeyRole::Unclassified => true,
        KeyRole::Root => root,
        KeyRole::Hot | KeyRole::Challenge => signs && !root && authorized("authentication"),
        KeyRole::Recovery => signs && !root && authorized("assertionMethod"),
        // A device key asserts on behalf of the device and speaks for the group;
        // the DID document must carry it under both relationships.
        KeyRole::DeviceSigning => {
            signs && !root && authorized("authentication") && authorized("assertionMethod")
        }
        KeyRole::KeyAgreement => agrees && !root && authorized("keyAgreement"),
    };
    if !valid {
        return Err(invalid());
    }
    Ok(())
}
fn snapshot(root: &Path, vault: &str, wrapped: &WrappedKey) -> Result<KeyRecord> {
    let layout = layout(root, vault)?;
    // Reject linked/unsafe envelopes, not just a valid JSON payload reached through a symlink.
    let meta = std::fs::symlink_metadata(layout.key_path(&wrapped.id.thumbprint)?)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != std::fs::metadata(layout.root())?.uid()
        || meta.mode() & 0o777 != 0o600
    {
        return Err(invalid());
    }
    let doc = document(&layout, &wrapped.id.did)?;
    verify_role(wrapped, &doc, &KeyRole::Unclassified)?;
    Ok(KeyRecord {
        key_id: uuid(),
        vault_id: vault.into(),
        did: wrapped.id.did.clone(),
        kid: wrapped.id.kid.clone(),
        role: KeyRole::Unclassified,
        purpose: String::new(),
        envelope_digest: digest(wrapped)?,
        document_digest: digest(&doc)?,
        state: "active".into(),
        identity_epoch: 0,
        generation: 0,
    })
}
pub(super) fn get_key(db: &Connection, key: &str) -> Result<KeyRecord> {
    db.query_row("SELECT key_id,vault_id,did,kid,role,purpose,envelope_digest,document_digest,state,identity_epoch,generation FROM keys WHERE key_id=?1", [key], |r| {
        let role: String = r.get(4)?;
        let role = match role.as_str() { "root" => KeyRole::Root, "hot" => KeyRole::Hot, "recovery" => KeyRole::Recovery, "challenge" => KeyRole::Challenge, "device_signing" => KeyRole::DeviceSigning, "key_agreement" => KeyRole::KeyAgreement, "unclassified" => KeyRole::Unclassified, _ => return Err(rusqlite::Error::InvalidQuery) };
        Ok(KeyRecord { key_id:r.get(0)?,vault_id:r.get(1)?,did:r.get(2)?,kid:r.get(3)?,role,purpose:r.get(5)?,envelope_digest:r.get(6)?,document_digest:r.get(7)?,state:r.get(8)?,identity_epoch:r.get(9)?,generation:r.get(10)? })
    }).optional().map_err(db_error)?.ok_or_else(invalid)
}
pub(super) fn validate_key(root: &Path, record: &KeyRecord) -> Result<()> {
    let layout = layout(root, &record.vault_id)?;
    let fragment = record
        .kid
        .strip_prefix(&format!("{}#", record.did))
        .ok_or_else(invalid)?;
    let wrapped = store::resolve(&layout, &record.did, Some(fragment))?;
    let current = snapshot(root, &record.vault_id, &wrapped)?;
    if record.envelope_digest != current.envelope_digest
        || record.document_digest != current.document_digest
    {
        return Err(invalid());
    }
    verify_role(&wrapped, &document(&layout, &record.did)?, &record.role)
}

pub(super) fn resolve(
    tx: &Connection,
    root: &Path,
    change: CatalogChange,
) -> Result<CatalogEffect> {
    Ok(match change {
        CatalogChange::EnrollVault { vault_id } => {
            active_vault(tx, &vault_id)?;
            let layout = layout(root, &vault_id)?;
            let mut keys = store::load_all(&layout)?
                .iter()
                .map(|w| snapshot(root, &vault_id, w))
                .collect::<Result<Vec<_>>>()?;
            let existing = list(tx)?
                .keys
                .into_iter()
                .filter(|k| k.vault_id == vault_id)
                .collect::<Vec<_>>();
            if existing
                .iter()
                .any(|k| !keys.iter().any(|n| n.kid == k.kid && n.did == k.did))
            {
                return Err(invalid());
            }
            for key in &mut keys {
                if let Some(old) = existing.iter().find(|k| k.kid == key.kid) {
                    key.key_id = old.key_id.clone();
                    key.generation = old.generation.checked_add(1).ok_or_else(invalid)?;
                    key.identity_epoch = old.identity_epoch.checked_add(1).ok_or_else(invalid)?;
                }
            }
            if keys.is_empty() || keys.len() > 64 {
                return Err(invalid());
            }
            let legacy_audit = Some(
                crate::audit::log::legacy_summary(&layout.audit_dir()).map_err(|_| invalid())?,
            );
            CatalogEffect::EnrollVault {
                vault_id,
                keys,
                legacy_audit,
            }
        }
        CatalogChange::ConfirmRole {
            key_id,
            role,
            purpose,
        } => {
            let before = get_key(tx, &key_id)?;
            active_vault(tx, &before.vault_id)?;
            if before.state != "active" || !purpose_valid(&role, &purpose) {
                return Err(invalid());
            }
            // The binding is set once. Re-stating it is not a way to re-key a
            // device signing key to another purpose under the same grants.
            if before.role == KeyRole::DeviceSigning && before.purpose != purpose {
                return Err(invalid());
            }
            validate_key(root, &before)?;
            let mut after = before.clone();
            after.role = role;
            after.purpose = purpose;
            validate_key(root, &after)?;
            CatalogEffect::ConfirmRole {
                before: Box::new(before),
                after: Box::new(after),
            }
        }
        CatalogChange::PublishPolicy {
            policy_id,
            version,
            content,
        } => {
            if !crate::principal::validate_uuid(&policy_id) || version == 0 {
                return Err(invalid());
            }
            let content = super::policy::normalize(content)?;
            let last: u32 = tx
                .query_row(
                    "SELECT COALESCE(MAX(version),0) FROM policies WHERE policy_id=?1",
                    [&policy_id],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if last.checked_add(1) != Some(version) {
                return Err(invalid());
            }
            let digest = digest(&content)?;
            let content = String::from_utf8(
                serde_json_canonicalizer::to_vec(&content).map_err(|_| invalid())?,
            )
            .map_err(|_| invalid())?;
            if content.len() > 8192 {
                return Err(invalid());
            }
            CatalogEffect::PublishPolicy {
                policy_id,
                version,
                content,
                digest,
            }
        }
        CatalogChange::InstallDocument {
            vault_id,
            document: doc,
        } => {
            active_vault(tx, &vault_id)?;
            let did = doc
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?
                .to_owned();
            crate::did::document::verify_path_binding(&did, &doc)?;
            if serde_json::to_vec(&doc)?.len() > 32768 {
                return Err(invalid());
            }
            let old = document(&layout(root, &vault_id)?, &did)?;
            if crate::did::lifecycle::is_deactivated(&old) {
                return Err(invalid());
            }
            // A root-signed replacement may retire a hot key. Root/recovery
            // methods cannot silently disappear through this operation.
            for key in list(tx)?
                .keys
                .into_iter()
                .filter(|k| k.vault_id == vault_id && k.did == did && k.state == "active")
            {
                validate_key(root, &key)?;
                let l = layout(root, &vault_id)?;
                let fragment = key
                    .kid
                    .strip_prefix(&format!("{did}#"))
                    .ok_or_else(invalid)?;
                let wrapped = store::resolve(&l, &did, Some(fragment))?;
                if !crate::did::lifecycle::is_deactivated(&doc) {
                    if matches!(key.role, KeyRole::Hot | KeyRole::DeviceSigning)
                        && anp::authentication::find_verification_method(&doc, &key.kid).is_none()
                    {
                        continue;
                    }
                    verify_role(&wrapped, &doc, &key.role)?;
                }
            }
            CatalogEffect::InstallDocument {
                vault_id,
                did,
                before_digest: digest(&old)?,
                after_digest: digest(&doc)?,
                document: doc,
            }
        }
    })
}

pub(super) fn apply(
    tx: &Transaction<'_>,
    root: &Path,
    operation: &str,
    effect: CatalogEffect,
) -> Result<()> {
    match effect {
        CatalogEffect::EnrollVault {
            vault_id,
            keys,
            legacy_audit,
        } => {
            let current = crate::audit::log::legacy_summary(&layout(root, &vault_id)?.audit_dir())
                .map_err(|_| invalid())?;
            if legacy_audit.as_ref() != Some(&current) {
                return Err(invalid());
            }
            append(
                tx,
                &json!({"event":"LEGACY_AUDIT_LINKED","vault_id":vault_id,"history":current}),
            )?;
            active_vault(tx, &vault_id)?;
            // Bind the complete inventory, including additions since PREPARE.
            let current = store::load_all(&layout(root, &vault_id)?)?;
            if current.len() != keys.len() {
                return Err(invalid());
            }
            tx.execute("UPDATE grants SET state='revoked' WHERE key_id IN (SELECT key_id FROM keys WHERE vault_id=?1) AND state='active'",[&vault_id]).map_err(db_error)?;
            for key in keys {
                validate_key(root, &key)?;
                tx.execute("INSERT INTO keys(key_id,vault_id,did,kid,role,purpose,envelope_digest,state,identity_epoch,generation,document_digest) VALUES(?1,?2,?3,?4,'unclassified','',?5,'active',?7,?8,?6) ON CONFLICT(vault_id,kid) DO UPDATE SET role='unclassified',purpose='',envelope_digest=excluded.envelope_digest,document_digest=excluded.document_digest,state='active',identity_epoch=excluded.identity_epoch,generation=excluded.generation", params![key.key_id,key.vault_id,key.did,key.kid,key.envelope_digest,key.document_digest,key.identity_epoch,key.generation]).map_err(db_error)?;
            }
        }
        CatalogEffect::ConfirmRole { before, after } => {
            if get_key(tx, &before.key_id)? != *before {
                return Err(invalid());
            }
            active_vault(tx, &before.vault_id)?;
            validate_key(root, &after)?;
            tx.execute("UPDATE keys SET role=?1,purpose=?2,generation=generation+1,identity_epoch=identity_epoch+1 WHERE key_id=?3",params![after.role.name(),after.purpose,after.key_id]).map_err(db_error)?;
            tx.execute(
                "UPDATE grants SET state='revoked' WHERE key_id=?1 AND state='active'",
                [after.key_id],
            )
            .map_err(db_error)?;
        }
        CatalogEffect::PublishPolicy {
            policy_id,
            version,
            content,
            digest: hash,
        } => {
            tx.execute(
                "INSERT INTO policies VALUES(?1,?2,?3,?4)",
                params![policy_id, version, content, hash],
            )
            .map_err(db_error)?;
        }
        CatalogEffect::InstallDocument {
            vault_id,
            did,
            before_digest,
            document: doc,
            after_digest,
        } => {
            active_vault(tx, &vault_id)?;
            // Recheck every enrolled envelope and role immediately before making
            // the durable intent; PREPARE is not permission to trust changed files.
            resolve(
                tx,
                root,
                CatalogChange::InstallDocument {
                    vault_id: vault_id.clone(),
                    document: doc.clone(),
                },
            )?;
            if digest(&document(&layout(root, &vault_id)?, &did)?)? != before_digest
                || digest(&doc)? != after_digest
            {
                return Err(invalid());
            }
            crate::did::document::verify_path_binding(&did, &doc)?;
            tx.execute(
                "INSERT INTO file_operations VALUES(?1,?2,?3,?4,?5,?6,'pending')",
                params![
                    operation,
                    vault_id,
                    did,
                    before_digest,
                    after_digest,
                    serde_json::to_vec(&doc)?
                ],
            )
            .map_err(db_error)?;
            tx.execute(
                "UPDATE vaults SET state='maintenance' WHERE vault_id=?1 AND state='active'",
                [&vault_id],
            )
            .map_err(db_error)?;
            tx.execute("UPDATE keys SET state='maintenance',generation=generation+1 WHERE vault_id=?1 AND state='active'",[&vault_id]).map_err(db_error)?;
            tx.execute("UPDATE grants SET state='revoked' WHERE key_id IN (SELECT key_id FROM keys WHERE vault_id=?1) AND state='active'",[&vault_id]).map_err(db_error)?;
        }
    }
    Ok(())
}

pub(super) fn recover_files(db: &mut Connection, root: &Path) -> Result<()> {
    let entries: Vec<(String, String, String, String, String, Vec<u8>)> = {
        let mut statement = db.prepare("SELECT operation_id,vault_id,did,before_digest,after_digest,document FROM file_operations WHERE state='pending' ORDER BY operation_id").map_err(db_error)?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                ))
            })
            .map_err(db_error)?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(db_error)?
    };
    for (operation, vault, did, before, after, bytes) in entries {
        let target: Value = serde_json::from_slice(&bytes).map_err(|_| unavailable())?;
        let (payload,approved_digest,actor,epoch,boot,expires,monotonic): (String,String,u32,i64,i64,i64,i64) = db.query_row("SELECT payload,digest,actor,identity_epoch,boot_epoch,expires_at,monotonic_deadline FROM admin_operations WHERE operation_id=?1 AND state='committed'",[&operation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(db_error)?;
        let resolved: Resolved = serde_json::from_str(&payload).map_err(|_| unavailable())?;
        let binding = json!({"operation_id":operation,"actor":actor,"boot_epoch":boot,"epoch":epoch,"expires_at":expires,"monotonic_deadline":monotonic,"effect":serde_json::to_value(&resolved).map_err(|_|unavailable())?});
        if digest(&binding)? != approved_digest {
            return Err(unavailable());
        }
        match resolved {
            Resolved::RotateHotKey {
                root: key,
                unsigned,
                ..
            } if key.vault_id == vault
                && key.did == did
                && key.document_digest == before
                && crate::did::lifecycle::strip_proof(&target)? == unsigned
                && target["proof"]["verificationMethod"] == key.kid => {}
            Resolved::Catalog { effect } => match *effect {
                CatalogEffect::InstallDocument {
                    vault_id,
                    did: subject,
                    before_digest,
                    after_digest,
                    document,
                } if vault_id == vault
                    && subject == did
                    && before_digest == before
                    && after_digest == after
                    && document == target => {}
                _ => return Err(unavailable()),
            },
            _ => return Err(unavailable()),
        }
        let approved = {
            let mut events = db
                .prepare("SELECT event_data FROM audit_events")
                .map_err(db_error)?;
            let mut rows = events.query([]).map_err(db_error)?;
            let mut found = false;
            while let Some(row) = rows.next().map_err(db_error)? {
                let data: Vec<u8> = row.get(0).map_err(db_error)?;
                let event: Value = serde_json::from_slice(&data).map_err(|_| unavailable())?;
                if event["event"] == "OPERATION_COMMITTED"
                    && event["operation_id"] == operation
                    && event["digest"] == approved_digest
                {
                    found = true;
                }
            }
            found
        };
        if !approved {
            return Err(unavailable());
        }
        if digest(&target)? != after {
            return Err(unavailable());
        }
        crate::did::document::verify_path_binding(&did, &target)?;
        let layout = layout(root, &vault)?;
        let current = digest(&document(&layout, &did)?)?;
        if current != before && current != after {
            return Err(unavailable());
        }
        if current != after {
            store::write_did_document(&layout, &did, &target)?;
        }
        // write_atomic syncs file and parent; recheck exactly what is installed.
        if digest(&document(&layout, &did)?)? != after {
            return Err(unavailable());
        }
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        tx.execute("UPDATE keys SET document_digest=?1,identity_epoch=identity_epoch+1 WHERE vault_id=?2 AND did=?3",params![after,vault,did]).map_err(db_error)?;
        tx.execute("UPDATE keys SET state=CASE WHEN did=?1 AND ?2 THEN 'retired' ELSE 'active' END WHERE vault_id=?3 AND state='maintenance'",params![did,crate::did::lifecycle::is_deactivated(&target),vault]).map_err(db_error)?;
        for key in list(&tx)?.keys.into_iter().filter(|k| {
            k.vault_id == vault
                && k.did == did
                && matches!(k.role, KeyRole::Hot | KeyRole::DeviceSigning)
        }) {
            if anp::authentication::find_verification_method(&target, &key.kid).is_none() {
                tx.execute(
                    "UPDATE keys SET state='retired' WHERE key_id=?1",
                    [key.key_id],
                )
                .map_err(db_error)?;
            }
        }
        tx.execute(
            "UPDATE vaults SET state='active' WHERE vault_id=?1",
            [vault],
        )
        .map_err(db_error)?;
        tx.execute(
            "UPDATE file_operations SET state='complete' WHERE operation_id=?1",
            [&operation],
        )
        .map_err(db_error)?;
        append(
            &tx,
            &json!({"event":"FILE_OPERATION_COMPLETED","operation_id":operation,"digest":after}),
        )?;
        tx.commit().map_err(db_error)?;
    }
    Ok(())
}

pub(super) fn list(db: &Connection) -> Result<Catalog> {
    let mut statement = db
        .prepare("SELECT key_id FROM keys ORDER BY key_id")
        .map_err(db_error)?;
    let ids = statement
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(db_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(db_error)?;
    let keys = ids
        .iter()
        .map(|id| get_key(db, id))
        .collect::<Result<Vec<_>>>()?;
    let mut statement = db
        .prepare("SELECT vault_id,state FROM vaults ORDER BY vault_id")
        .map_err(db_error)?;
    let vaults = statement
        .query_map([], |r| {
            Ok(json!({"vault_id":r.get::<_,String>(0)?,"state":r.get::<_,String>(1)?}))
        })
        .map_err(db_error)?
        .collect::<std::result::Result<_, _>>()
        .map_err(db_error)?;
    let mut statement = db
        .prepare("SELECT policy_id,version,content,digest FROM policies ORDER BY policy_id,version")
        .map_err(db_error)?;
    let policies = statement.query_map([],|r| Ok(json!({"policy_id":r.get::<_,String>(0)?,"version":r.get::<_,u32>(1)?,"content":r.get::<_,String>(2)?,"digest":r.get::<_,String>(3)?}))).map_err(db_error)?.collect::<std::result::Result<_,_>>().map_err(db_error)?;
    Ok(Catalog {
        vaults,
        keys,
        policies,
    })
}
pub(super) fn check_key(
    db: &Connection,
    root: &Path,
    vault: &str,
    did: &str,
    kid: &str,
) -> Result<()> {
    active_vault(db, vault)?;
    let id: Option<String> = db.query_row("SELECT key_id FROM keys WHERE vault_id=?1 AND did=?2 AND kid=?3 AND state='active' AND role!='unclassified'",params![vault,did,kid],|r|r.get(0)).optional().map_err(db_error)?;
    validate_key(root, &get_key(db, &id.ok_or_else(invalid)?)?)
}
