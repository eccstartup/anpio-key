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
        if wrapped.algorithm == crate::keystore::record::KeyAlgorithm::P256 {
            return Err(KeydError::Misuse("unsupported migration key".into()));
        }
        // 指纹按曲线各算一遍，并且必须和信封上写着的那一种曲线一起对：
        // 一个 `e1_` 信封配一把 X25519 方法（或反过来）既不是"不支持"，
        // 也不是"钥匙丢了"，而是文档和信封说的不是同一件事。
        match (&material, wrapped.algorithm) {
            (anp::PublicKeyMaterial::Ed25519(pk), crate::keystore::record::KeyAlgorithm::Ed25519) => {
                if crate::crypto::thumbprint::e1_segment(pk)? != wrapped.id.thumbprint {
                    return Err(KeydError::Misuse("migration key/document mismatch".into()));
                }
            }
            (
                anp::PublicKeyMaterial::X25519(bytes),
                crate::keystore::record::KeyAlgorithm::X25519,
            ) => {
                let public = x25519_dalek::PublicKey::from(*bytes);
                if crate::crypto::thumbprint::x1_segment(&public) != wrapped.id.thumbprint {
                    return Err(KeydError::Misuse("migration key/document mismatch".into()));
                }
            }
            _ => {
                return Err(KeydError::Misuse(
                    "migration key/document curve mismatch".into(),
                ))
            }
        }
        if let Some(tty) = tty.as_mut() {
            let pass =
                crate::tty::read_secret(tty, &format!("Verify recovery of {}: ", wrapped.id.kid))?;
            let key = unwrap::unlock(&wrapped, pass.as_bytes(), &device)?;
            let recovered = match &material {
                anp::PublicKeyMaterial::Ed25519(pk) => {
                    let message = b"anpio-key offline recovery self-test v1";
                    let signature = key.sign(message)?;
                    key.verify(message, &signature) && key.verifying_key()? == *pk
                }
                anp::PublicKeyMaterial::X25519(bytes) => {
                    key.x25519_public().is_ok_and(|public| public == *bytes)
                }
                // 上面那个 match 已经把其余曲线挡掉了；这里只是让类型闭合。
                _ => false,
            };
            if !recovered {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hygiene::LockedBytes;
    use crate::crypto::kdf::Argon2Config;
    use crate::keystore::record::{KeyAlgorithm, KeyId};
    use crate::keystore::wrap::{seal, seed_to_public, seed_to_x25519_public, SealRequest};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    const PASS: &[u8] = b"migration fixture passphrase";

    fn fast() -> Argon2Config {
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        }
    }

    fn seed(byte: u8) -> LockedBytes {
        LockedBytes::fill(|bytes| *bytes = [byte; 32]).unwrap()
    }

    fn device_secret() -> LockedBytes {
        LockedBytes::fill(|bytes| *bytes = [7u8; 32]).unwrap()
    }

    /// A DID-bound store with one root, one device signing and one agreement key,
    /// all sealed and written the way `bind-did` writes them.
    struct Fixture {
        dir: PathBuf,
        did: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn write_key(
        layout: &KeydLayout,
        did: &str,
        fragment: &str,
        algorithm: KeyAlgorithm,
        thumbprint: &str,
        public_multibase: &str,
        seed: &LockedBytes,
    ) {
        let wrapped = seal(SealRequest {
            id: KeyId {
                did: did.to_string(),
                kid: format!("{did}#{fragment}"),
                thumbprint: thumbprint.to_string(),
            },
            algorithm,
            public_multibase: public_multibase.to_string(),
            label: "migration".into(),
            name: String::new(),
            passphrase: PASS,
            device_secret: &device_secret(),
            seed,
            argon: fast(),
            hardware: None,
        })
        .unwrap();
        store::write(layout, &wrapped).unwrap();
    }

    fn fixture(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!(
            "keyd-migrate-{tag}-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let layout = KeydLayout::at(dir.clone());
        layout.ensure().unwrap();
        std::fs::write(layout.device_secret_path(), [7u8; 32]).unwrap();
        std::fs::set_permissions(
            layout.device_secret_path(),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let root_seed = seed(1);
        let sign_seed = seed(2);
        let agreement_seed = seed(3);
        let (root_public, root_mb) = seed_to_public(&root_seed);
        let (sign_public, sign_mb) = seed_to_public(&sign_seed);
        let (agreement_public, agreement_mb) = seed_to_x25519_public(&agreement_seed);

        use anp::authentication::DidVerificationRelationship as Relationship;
        let spec =
            crate::did::document::DidDocumentSpec::new("example.com", vec!["user".into(), "alice".into()]);
        let (did, unsigned) = crate::did::document::build_unsigned_with(
            &spec,
            &root_public,
            vec![
                crate::did::document::ExtraKey::new(
                    "alice-default-sign",
                    sign_public,
                    vec![Relationship::Authentication, Relationship::AssertionMethod],
                ),
                crate::did::document::ExtraKey::agreement(
                    "alice-default-agreement",
                    agreement_public,
                    vec![Relationship::KeyAgreement],
                ),
            ],
        )
        .unwrap();
        let root_kid = format!("{did}#key-1");
        let signing_key = crate::sign::LockedSigningKey::from_seed(
            KeyId {
                did: String::new(),
                kid: String::new(),
                thumbprint: String::new(),
            },
            seed(1),
        )
        .unwrap();
        let document = crate::did::document::sign_document(&unsigned, &signing_key, &root_kid)
            .unwrap();
        store::write_did_document(&layout, &did, &document).unwrap();

        let root_thumb = crate::crypto::thumbprint::e1_segment(&root_public).unwrap();
        let sign_thumb = crate::crypto::thumbprint::e1_segment(&sign_public).unwrap();
        let agreement_thumb = crate::crypto::thumbprint::x1_segment(
            &x25519_dalek::PublicKey::from(agreement_public),
        );
        write_key(&layout, &did, "key-1", KeyAlgorithm::Ed25519, &root_thumb, &root_mb, &root_seed);
        write_key(
            &layout,
            &did,
            "alice-default-sign",
            KeyAlgorithm::Ed25519,
            &sign_thumb,
            &sign_mb,
            &sign_seed,
        );
        write_key(
            &layout,
            &did,
            "alice-default-agreement",
            KeyAlgorithm::X25519,
            &agreement_thumb,
            &agreement_mb,
            &agreement_seed,
        );

        Fixture { dir, did }
    }

    /// Swap the envelope at `fragment` for a fresh one sealed from `seed`, keeping
    /// the kid the document names. The document is untouched, so the envelope and
    /// the document now say different things about that key.
    fn replace_key(
        dir: &Path,
        did: &str,
        fragment: &str,
        algorithm: KeyAlgorithm,
        key_seed: &LockedBytes,
    ) {
        let layout = KeydLayout::at(dir.to_path_buf());
        let kid = format!("{did}#{fragment}");
        for wrapped in store::load_all(&layout).unwrap() {
            if wrapped.id.kid == kid {
                store::delete(&layout, &wrapped.id.thumbprint).unwrap();
            }
        }
        match algorithm {
            KeyAlgorithm::Ed25519 => {
                let (public, multibase) = seed_to_public(key_seed);
                let thumbprint = crate::crypto::thumbprint::e1_segment(&public).unwrap();
                write_key(&layout, did, fragment, algorithm, &thumbprint, &multibase, key_seed);
            }
            KeyAlgorithm::X25519 => {
                let (public, multibase) = seed_to_x25519_public(key_seed);
                let thumbprint = crate::crypto::thumbprint::x1_segment(
                    &x25519_dalek::PublicKey::from(public),
                );
                write_key(&layout, did, fragment, algorithm, &thumbprint, &multibase, key_seed);
            }
            other => panic!("the fixture only speaks Ed25519 and X25519, not {other:?}"),
        }
    }

    #[test]
    fn inspect_accepts_ed25519_and_x25519_keys() {
        let fixture = fixture("accept");
        let report = inspect(&fixture.dir, false).unwrap();
        let keys = report["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 3, "{report}");
        let kids: Vec<&str> = keys.iter().filter_map(|key| key["kid"].as_str()).collect();
        for fragment in ["key-1", "alice-default-sign", "alice-default-agreement"] {
            let kid = format!("{}#{fragment}", fixture.did);
            assert!(kids.contains(&kid.as_str()), "{fragment} missing from {kids:?}");
        }
        assert!(keys.iter().all(|key| key["role"] == json!("unclassified")));
        assert_eq!(report["recovery_verified"], json!(false));
    }

    #[test]
    fn inspect_rejects_an_ed25519_envelope_that_does_not_match_the_document() {
        let fixture = fixture("ed25519-mismatch");
        replace_key(
            &fixture.dir,
            &fixture.did,
            "alice-default-sign",
            KeyAlgorithm::Ed25519,
            &seed(4),
        );
        let err = inspect(&fixture.dir, false).unwrap_err();
        assert!(
            err.to_string().contains("migration key/document mismatch"),
            "{err}"
        );
    }

    #[test]
    fn inspect_rejects_an_x25519_envelope_that_does_not_match_the_document() {
        let fixture = fixture("x25519-mismatch");
        replace_key(
            &fixture.dir,
            &fixture.did,
            "alice-default-agreement",
            KeyAlgorithm::X25519,
            &seed(4),
        );
        let err = inspect(&fixture.dir, false).unwrap_err();
        assert!(
            err.to_string().contains("migration key/document mismatch"),
            "{err}"
        );
    }

    #[test]
    fn inspect_rejects_a_curve_the_document_does_not_bind() {
        let fixture = fixture("curve-mismatch");
        // The document names an X25519 key at this kid; an Ed25519 envelope under
        // the same kid is neither "unsupported" nor "missing" — it is the wrong
        // curve for a key the document just published.
        replace_key(
            &fixture.dir,
            &fixture.did,
            "alice-default-agreement",
            KeyAlgorithm::Ed25519,
            &seed(4),
        );
        let err = inspect(&fixture.dir, false).unwrap_err();
        assert!(
            err.to_string().contains("migration key/document curve mismatch"),
            "{err}"
        );
    }

    #[test]
    fn inspect_refuses_a_store_others_can_write_to() {
        let fixture = fixture("permissions");
        let layout = KeydLayout::at(fixture.dir.clone());
        std::fs::set_permissions(layout.keys_dir(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        let err = inspect(&fixture.dir, false).unwrap_err();
        assert!(err.to_string().contains("unsafe migration directory"), "{err}");
    }
}
