//! Read-only legacy inventory and recovery verification. Never exports a seed.
use crate::error::{KeydError, Result};
use crate::keystore::{device, layout::KeydLayout, store, unwrap};
use crate::sign::Signer;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Inspect only the files needed to recover an identity. Runtime sockets/logs
/// are deliberately excluded. The offline installer owns freezing old writers.
pub fn inspect(path: &Path, verify: bool) -> Result<Value> {
    let layout = KeydLayout::at(path.to_path_buf());
    let uid = std::fs::symlink_metadata(path)?.uid();
    for dir in [path.to_path_buf(), layout.keys_dir(), layout.dids_dir()] {
        let m = std::fs::symlink_metadata(dir)?;
        if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
            return Err(KeydError::Permission("unsafe migration directory".into()));
        }
    }
    let check_file = |file: &Path, secret: bool| -> Result<()> {
        let m = std::fs::symlink_metadata(file)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != uid
            || m.mode() & 0o022 != 0
            || (secret && m.mode() & 0o077 != 0)
            || m.len() > 1_048_576
        {
            return Err(KeydError::Permission("unsafe migration file".into()));
        }
        Ok(())
    };
    check_file(&layout.device_secret_path(), true)?;
    for entry in std::fs::read_dir(layout.keys_dir())? {
        check_file(&entry?.path(), true)?;
    }
    for entry in std::fs::read_dir(layout.dids_dir())? {
        check_file(&entry?.path(), false)?;
    }
    let device = device::load(&layout)?;
    let keys = store::load_all(&layout)?;
    if keys.is_empty() || keys.len() > 64 {
        return Err(KeydError::Misuse("migration requires 1..64 keys".into()));
    }
    let mut seen = BTreeSet::new();
    let mut inventory = Vec::new();
    let mut tty = if verify {
        Some(crate::tty::open()?)
    } else {
        None
    };
    for wrapped in keys {
        check_file(&layout.key_path(&wrapped.id.thumbprint)?, true)?;
        wrapped.validate()?;
        wrapped.verify_aad()?;
        if !seen.insert(wrapped.id.kid.clone()) {
            return Err(KeydError::Misuse("duplicate migration kid".into()));
        }
        check_file(&layout.did_path(&wrapped.id.did), false)?;
        let doc = store::read_did_document(&layout, &wrapped.id.did)?;
        crate::did::document::verify_path_binding(&wrapped.id.did, &doc)?;
        let method = anp::authentication::find_verification_method(&doc, &wrapped.id.kid)
            .ok_or_else(|| KeydError::Misuse("envelope missing from document".into()))?;
        let material = anp::authentication::extract_public_key(&method)
            .map_err(|_| KeydError::Misuse("invalid migration public key".into()))?;
        let anp::PublicKeyMaterial::Ed25519(pk) = material else {
            return Err(KeydError::Misuse("unsupported migration key".into()));
        };
        if crate::crypto::thumbprint::e1_segment(&pk)? != wrapped.id.thumbprint {
            return Err(KeydError::Misuse("migration key/document mismatch".into()));
        }
        if let Some(tty) = tty.as_mut() {
            let pass =
                crate::tty::read_secret(tty, &format!("Verify recovery of {}: ", wrapped.id.kid))?;
            let key = unwrap::unlock(&wrapped, pass.as_bytes(), &device)?;
            let message = b"anpio-key offline recovery self-test v1";
            let signature = key.sign(message)?;
            if !key.verify(message, &signature) || key.verifying_key() != pk {
                return Err(KeydError::Misuse(
                    "migration recovery self-test failed".into(),
                ));
            }
        }
        inventory.push(json!({"did":wrapped.id.did,"kid":wrapped.id.kid,
            "thumbprint":wrapped.id.thumbprint,"version":wrapped.version,
            "hardware":wrapped.hardware,"role":"unclassified"}));
    }
    let legacy = crate::audit::log::legacy_summary(&layout.audit_dir())?;
    Ok(
        json!({"format":"anpio-key-migration-inspection-v1", "keys":inventory,
        "legacy_audit":legacy,"recovery_verified":verify,
        "historical_copies_revoked":false}),
    )
}
