use super::*;

struct Fixture {
    db: Database,
    config: ServiceConfig,
    dir: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("keyd-db-test-{}", uuid()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("state.sqlite");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let config:ServiceConfig=serde_json::from_value(json!({
            "schema_version":1,"mode":if cfg!(target_os = "macos") { "macos-boundary-preview" } else { "linux-boundary-preview" },"instance_id":uuid(),
            "service_uid":1001,"admin_uids":[1002],"agent_gid":1003,"admin_gid":1004,
            "state_dir":"/var/lib/anpio-key","sign_socket":"/run/anpio-key/sign/sign.sock","admin_socket":"/run/anpio-key/admin/admin.sock",
            "principals":[{"principal_id":uuid(),"uid":1005,"generation":1,"enabled":true}],"vault_ids":[]
        })).unwrap();
        config.validate().unwrap();
        let mut connection = open_new(&path).unwrap();
        Database::create(&mut connection, &config, now()).unwrap();
        let mut db = Database {
            connection,
            boot_epoch: 0,
            root: dir.clone(),
        };
        db.recovery(&config, now()).unwrap();
        Self { db, config, dir }
    }
    fn disable(&mut self) -> Prepared {
        self.db
            .prepare(
                1002,
                Change::DisablePrincipal {
                    principal_id: self.config.principals[0].principal_id.clone(),
                },
                now(),
            )
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn now() -> Time {
    Time {
        wall: 1_000,
        monotonic_ms: 10_000,
    }
}

#[test]
fn se_session_loss_revokes_exhausted_cached_results_and_old_approvals() {
    let (mut f, key, policy) = grant_fixture();
    let grant = new_grant(&mut f, &key, &policy);
    let id = uuid();
    f.db.reserve_http(&grant.principal_id, &grant.grant_id, &id, &canonical(), now()).unwrap();
    f.db.complete_http(&grant.principal_id, &id, &json!({"signature":"cached"}), (1040, 45000), "digest", now()).unwrap();
    f.db.connection.execute("UPDATE grants SET state='exhausted',used_uses=max_uses WHERE grant_id=?1", [&grant.grant_id]).unwrap();
    assert!(f.db.request_status(&grant.principal_id, &id, now()).unwrap().result.is_some());
    let approval = f.disable();
    let epoch = f.db.mutation_epoch().unwrap();
    f.db.end_se_session(1002, "old-session").unwrap();
    assert!(f.db.request_status(&grant.principal_id, &id, now()).unwrap().result.is_none());
    let after = grants::get(&f.db.connection, &grant.grant_id).unwrap().unwrap();
    assert_eq!(after.state, "revoked");
    assert_eq!(after.used_uses, grant.max_uses);
    assert!(f.db.commit(1002, &approval.operation_id, &approval.digest, now()).is_err());
    assert!(f.db.mutation_epoch().unwrap() > epoch);
}

#[test]
fn se_session_end_audit_failure_rolls_back_all_authority_mutations() {
    let (mut f, key, policy) = grant_fixture();
    let grant = new_grant(&mut f, &key, &policy);
    let approval = f.disable();
    let epoch = f.db.mutation_epoch().unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_session_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();
    assert!(f.db.end_se_session(1002, "old-session").is_err());
    assert_eq!(f.db.mutation_epoch().unwrap(), epoch);
    assert_eq!(grants::get(&f.db.connection, &grant.grant_id).unwrap().unwrap().state, "active");
    f.db.connection.execute_batch("DROP TRIGGER fail_session_audit").unwrap();
    f.db.commit(1002, &approval.operation_id, &approval.digest, now()).unwrap();
}

#[cfg(all(target_os = "macos", feature = "hardware-se"))]
#[test]
#[ignore = "explicit local-console bridge test with synthetic HS; no real keychain keys"]
fn local_console_se_bridge_signs_and_disconnect_revokes_without_hardware_mock_claims() {
    use crate::persistence::clock::{Clock, SystemClock};
    for ending in ["disconnect", "replay", "silence", "bad-pass", "bad-hs"] {
    let (mut f, key_id, policy) = grant_fixture();
    let key = f.db.catalog().unwrap().keys.into_iter().find(|key| key.key_id == key_id).unwrap();
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&key.vault_id));
    let old = crate::keystore::store::resolve(&layout, &key.did, Some("http-hot")).unwrap();
    let wrapped = crate::keystore::unwrap::rewrap_test_se(&old, b"test-pass", &crate::keystore::device::load(&layout).unwrap());
    crate::keystore::store::write(&layout, &wrapped).unwrap();
    apply_change(&mut f, catalog::CatalogChange::EnrollVault { vault_id: key.vault_id.clone() });
    apply_change(&mut f, catalog::CatalogChange::ConfirmRole { key_id: key_id.clone(), role: catalog::KeyRole::Hot });
    let grant = new_grant(&mut f, &key_id, &policy);
    let current = SystemClock.now().unwrap();
    f.db.connection.execute("UPDATE grants SET expiry=?1 WHERE grant_id=?2", params![current.wall + 120, grant.grant_id]).unwrap();
    f.db.connection.execute("UPDATE grant_deadlines SET monotonic_deadline=?1 WHERE grant_id=?2", params![current.monotonic_ms + 120_000, grant.grant_id]).unwrap();
    let mut config = f.config.clone();
    config.admin_uids = vec![crate::daemon::peer::self_uid()];
    config.state_dir = f.dir.clone();
    config.vault_ids = vec![key.vault_id];
    let placeholder = Database { connection: Connection::open_in_memory().unwrap(), boot_epoch: 0, root: f.dir.clone() };
    let database = std::mem::replace(&mut f.db, placeholder);
    f.db = crate::security::server::exercise_local_se_bridge(config, database, grant, ending);
    if ending == "bad-pass" || ending == "bad-hs" {
        let count: i64 = f.db.connection.query_row("SELECT count(*) FROM audit_events WHERE json_extract(CAST(event_data AS TEXT),'$.event')='SE_SESSION_REFUSED'", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1, "failed bridge unlock must be audited without plaintext secrets");
    }
    }
}

#[test]
fn prepared_operations_bind_actor_digest_epoch_and_single_use() {
    let mut f = Fixture::new();
    let p = f.disable();
    assert!(f.db.commit(999, &p.operation_id, &p.digest, now()).is_err());
    assert!(f.db.commit(1002, &p.operation_id, "wrong", now()).is_err());
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    assert!(f.db.principal(1005).unwrap().is_none());
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    let fresh =
        f.db.prepare(1002, Change::RegisterPrincipal { uid: 1005 }, now())
            .unwrap();
    assert_ne!(
        fresh.effect["principal_id"],
        f.config.principals[0].principal_id
    );
    assert_eq!(fresh.effect["generation"], 2);
    f.db.commit(1002, &fresh.operation_id, &fresh.digest, now())
        .unwrap();
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(f.db.principal(1005).unwrap().unwrap().generation, 2);
}

#[test]
fn stale_approvals_and_payload_replacement_cannot_mutate_state() {
    let mut f = Fixture::new();
    let stale = f.disable();
    let another =
        f.db.prepare(1002, Change::RegisterPrincipal { uid: 1006 }, now())
            .unwrap();
    f.db.commit(1002, &another.operation_id, &another.digest, now())
        .unwrap();
    assert!(f
        .db
        .commit(1002, &stale.operation_id, &stale.digest, now())
        .is_err());
    let p = f.disable();
    f.db.connection.execute("UPDATE admin_operations SET payload=?1 WHERE operation_id=?2",params![r#"{"kind":"RegisterPrincipal","uid":1007,"principal_id":"replaced","generation":1}"#,p.operation_id]).unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f.db.principal(1007).unwrap().is_none());
    assert!(f.db.principal(1005).unwrap().is_some());
}

#[test]
fn deadline_checks_include_monotonic_time_and_restart_invalidates_approval() {
    let mut f = Fixture::new();
    let p = f.disable();
    assert!(f
        .db
        .commit(
            1002,
            &p.operation_id,
            &p.digest,
            Time {
                wall: 999,
                monotonic_ms: 130_001
            }
        )
        .is_err());
    assert!(f
        .db
        .commit(
            1002,
            &p.operation_id,
            &p.digest,
            Time {
                wall: 1_121,
                monotonic_ms: 10_001
            }
        )
        .is_err());
    let boot = f.db.boot_epoch;
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(f.db.boot_epoch, boot + 1);
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f.db.principal(1005).unwrap().is_some());
}

#[test]
fn audit_failure_rolls_back_both_preparation_and_commit() {
    let mut f = Fixture::new();
    f.db.connection.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
    assert!(f
        .db
        .prepare(1002, Change::RegisterPrincipal { uid: 1007 }, now())
        .is_err());
    assert_eq!(
        f.db.connection
            .query_row("SELECT count(*) FROM admin_operations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    f.db.connection
        .execute_batch("DROP TRIGGER fail_audit")
        .unwrap();
    let p = f.disable();
    f.db.connection.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f.db.principal(1005).unwrap().is_some());
    let state: String =
        f.db.connection
            .query_row(
                "SELECT state FROM admin_operations WHERE operation_id=?1",
                [p.operation_id],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(state, "prepared");
}

#[test]
fn recovery_preserves_consumption_and_marks_incomplete_requests_unknown() {
    let mut f = Fixture::new();
    let principal = &f.config.principals[0].principal_id;
    f.db.connection.execute_batch("INSERT INTO vaults VALUES('vault','vaults/vault','active'); INSERT INTO keys VALUES('key','vault','did','did#hot','hot','digest','active',0,0,''); INSERT INTO policies VALUES('policy',1,'{}','digest');").unwrap();
    f.db.connection
        .execute(
            "INSERT INTO grants VALUES('grant',?1,'key','policy',1,1,9999,'request',0,2,1,0,0,'active')",
            [principal],
        )
        .unwrap();
    f.db.connection
        .execute(
            "INSERT INTO requests VALUES(?1,'request','grant','digest','reserved',NULL,NULL)",
            [principal],
        )
        .unwrap();
    assert!(f
        .db
        .connection
        .execute("UPDATE grants SET used_uses=3", [])
        .is_err());
    assert!(f
        .db
        .connection
        .execute("UPDATE policies SET content='changed'", [])
        .is_err());
    f.db.recovery(&f.config, now()).unwrap();
    let (state, uses): (String, i64) =
        f.db.connection
            .query_row("SELECT state,used_uses FROM grants", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((state.as_str(), uses), ("revoked_restart", 1));
    let state: String =
        f.db.connection
            .query_row("SELECT state FROM requests", [], |r| r.get(0))
            .unwrap();
    assert_eq!(state, "outcome_unknown");
}

#[test]
fn missing_future_corrupt_and_foreign_instance_databases_are_refused() {
    let mut f = Fixture::new();
    let missing = f.dir.join("missing.sqlite");
    assert!(open(&missing).is_err());
    assert!(!missing.exists());
    let mut foreign = f.config.clone();
    foreign.instance_id = uuid();
    assert!(f.db.recovery(&foreign, now()).is_err());
    f.db.connection
        .pragma_update(None, "user_version", SCHEMA + 1)
        .unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
    f.db.connection
        .pragma_update(None, "user_version", SCHEMA)
        .unwrap();
    f.db.connection
        .execute("UPDATE audit_events SET event_data=x'00' WHERE seq=1", [])
        .unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
}

#[test]
fn opening_newer_schema_does_not_rewrite_its_journal_mode() {
    let f = Fixture::new();
    f.db.connection
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA user_version=3;")
        .unwrap();
    assert!(open(&f.dir.join("state.sqlite")).is_err());
    let mode: String =
        f.db.connection
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
    assert_eq!(mode, "wal");
}

fn policy_value() -> Value {
    json!({"schema_version":1,"name":"read-orders","purpose":"http-authentication","origin":"https://service.example.com","methods":["GET"],"paths":["/v1/orders"],"query":{"mode":"none"},"body":{"mode":"empty","max_bytes":0},"signature_profile":"anp-http-v2","grant_limits":{"max_duration_seconds":900,"max_uses":100}})
}
fn apply_change(f: &mut Fixture, change: catalog::CatalogChange) -> Prepared {
    let p =
        f.db.prepare(1002, Change::Catalog { change }, now())
            .unwrap();
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    p
}
fn vault_fixture(f: &mut Fixture) -> (String, String, Value) {
    use crate::keystore::{create, hardware::HardwareChoice, layout::KeydLayout};
    let vault = uuid();
    let layout = KeydLayout::at(f.dir.join("vaults").join(&vault));
    layout.ensure().unwrap();
    let spec = crate::did::DidDocumentSpec::new("example.com", vec!["test".into()]);
    let created = create::create(
        &layout,
        &spec,
        "test",
        b"test-pass",
        crate::crypto::kdf::Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        HardwareChoice::None,
    )
    .unwrap();
    let secret = crate::keystore::device::load(&layout).unwrap();
    let key = crate::keystore::unwrap::unlock(&created.wrapped, b"test-pass", &secret).unwrap();
    let doc = crate::did::document::publishable(&spec, &created.did, &key).unwrap();
    crate::keystore::store::write_did_document(&layout, &created.did, &doc).unwrap();
    f.db.connection
        .execute(
            "INSERT INTO vaults VALUES(?1,?2,'active')",
            params![vault, format!("vaults/{vault}")],
        )
        .unwrap();
    (vault, created.did, doc)
}
#[test]
fn catalog_enrollment_never_infers_role_and_root_cannot_become_hot() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, _) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let key = f.db.catalog().unwrap().keys.remove(0);
    assert_eq!(key.role, KeyRole::Unclassified);
    assert!(f.db.check_key(&vault, &did, &key.kid).is_err());
    assert!(f
        .db
        .prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::ConfirmRole {
                    key_id: key.key_id.clone(),
                    role: KeyRole::Hot
                }
            },
            now()
        )
        .is_err());
    apply_change(
        &mut f,
        CatalogChange::ConfirmRole {
            key_id: key.key_id.clone(),
            role: KeyRole::Root,
        },
    );
    f.db.check_key(&vault, &did, &key.kid).unwrap();
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let migrated = f.db.catalog().unwrap().keys.remove(0);
    assert_eq!(migrated.key_id, key.key_id);
    assert_eq!(migrated.role, KeyRole::Unclassified);
    assert!(f.db.check_key(&vault, &did, &key.kid).is_err());
}
#[test]
fn policy_versions_are_immutable_and_unknown_fields_are_rejected() {
    use catalog::*;
    let mut f = Fixture::new();
    let id = uuid();
    apply_change(
        &mut f,
        CatalogChange::PublishPolicy {
            policy_id: id.clone(),
            version: 1,
            content: policy_value(),
        },
    );
    assert!(f
        .db
        .prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::PublishPolicy {
                    policy_id: id.clone(),
                    version: 1,
                    content: policy_value()
                }
            },
            now()
        )
        .is_err());
    let mut unknown = policy_value();
    unknown["unexpected"] = json!(true);
    let mut bad_origin = policy_value();
    bad_origin["origin"] = json!("https://example.com@evil.com");
    let mut query = policy_value();
    query["query"] = json!({"mode":"exact","value":"a=1&a=2"});
    for content in [unknown, bad_origin, query] {
        assert!(f
            .db
            .prepare(
                1002,
                Change::Catalog {
                    change: CatalogChange::PublishPolicy {
                        policy_id: id.clone(),
                        version: 2,
                        content
                    }
                },
                now()
            )
            .is_err());
    }
    apply_change(
        &mut f,
        CatalogChange::PublishPolicy {
            policy_id: id,
            version: 2,
            content: policy_value(),
        },
    );
    assert_eq!(f.db.catalog().unwrap().policies.len(), 2);
    assert!(f.db.connection.execute("DELETE FROM policies", []).is_err());
}
#[test]
fn enrollment_approval_binds_inventory_envelope_and_document() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, _, _) = vault_fixture(&mut f);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::EnrollVault {
                    vault_id: vault.clone(),
                },
            },
            now(),
        )
        .unwrap();
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    let path = layout.list_key_paths().unwrap().remove(0);
    let mut wrapped: crate::keystore::record::WrappedKey =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    wrapped.label = "changed after approval".into();
    crate::keystore::store::write(&layout, &wrapped).unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f.db.catalog().unwrap().keys.is_empty());
}
#[test]
fn journal_recovers_after_file_install_and_refuses_unknown_disk_state() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, doc) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    // Inject failure after installing a different, valid signed document.
    let updated = changed_document(&f, &vault, &did, &doc);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::InstallDocument {
                    vault_id: vault.clone(),
                    document: updated.clone(),
                },
            },
            now(),
        )
        .unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_completion BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%FILE_OPERATION_COMPLETED%' BEGIN SELECT RAISE(ABORT,'crash after rename'); END;").unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    let state: String =
        f.db.connection
            .query_row(
                "SELECT state FROM vaults WHERE vault_id=?1",
                [&vault],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(state, "maintenance");
    f.db.connection
        .execute_batch("DROP TRIGGER fail_completion")
        .unwrap();
    f.db.recovery(&f.config, now()).unwrap();
    let state: String =
        f.db.connection
            .query_row("SELECT state FROM file_operations", [], |r| r.get(0))
            .unwrap();
    assert_eq!(state, "complete");
    // An unknown document is never overwritten to manufacture successful recovery.
    f.db.connection
        .execute("UPDATE file_operations SET state='pending'", [])
        .unwrap();
    let path =
        crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault)).did_path(&did);
    std::fs::write(&path, b"{}").unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"{}");
}
#[test]
fn legacy_commands_reject_managed_vault_even_through_symlink() {
    let f = Fixture::new();
    let nested = f.dir.join("vaults").join(uuid());
    std::fs::create_dir_all(&nested).unwrap();
    assert!(crate::security::paths::deny_managed_directory(&nested).is_err());
    let alias = f.dir.with_extension("alias");
    std::os::unix::fs::symlink(&nested, &alias).unwrap();
    assert!(crate::security::paths::deny_managed_directory(&alias).is_err());
    std::fs::remove_file(alias).unwrap();
}

/// 把 schema-4 的库回退成 `version` 的样子,好让迁移链整段重跑。
///
/// `grants` 只能重建不能 DROP COLUMN:交叉列的 CHECK 让 SQLite 拒绝删列。
fn rewind_schema(c: &Connection, version: i64) {
    c.execute_batch(&format!(
        "PRAGMA foreign_keys=OFF;
         DROP TABLE IF EXISTS grant_operations;
         CREATE TABLE grants_old (
          grant_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL REFERENCES principals(principal_id),
          key_id TEXT NOT NULL REFERENCES keys(key_id), policy_id TEXT NOT NULL, policy_version INTEGER NOT NULL,
          boot_epoch INTEGER NOT NULL CHECK(boot_epoch>=0), expiry INTEGER NOT NULL,
          max_uses INTEGER NOT NULL CHECK(max_uses>0), used_uses INTEGER NOT NULL CHECK(used_uses>=0 AND used_uses<=max_uses),
          state TEXT NOT NULL CHECK(state IN ('active','revoked','revoked_restart','exhausted','expired')),
          FOREIGN KEY(policy_id,policy_version) REFERENCES policies(policy_id,version)
         ) STRICT;
         INSERT INTO grants_old SELECT grant_id,principal_id,key_id,policy_id,policy_version,boot_epoch,expiry,max_uses,used_uses,state FROM grants;
         DROP TABLE grants;
         ALTER TABLE grants_old RENAME TO grants;
         ALTER TABLE service_meta RENAME TO meta_old;
         CREATE TABLE service_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL CHECK(schema_version={version}),instance_id TEXT NOT NULL,boot_epoch INTEGER NOT NULL,mutation_epoch INTEGER NOT NULL) STRICT;
         INSERT INTO service_meta SELECT singleton,{version},instance_id,boot_epoch,mutation_epoch FROM meta_old;
         DROP TABLE meta_old;
         PRAGMA foreign_keys=ON;
         PRAGMA user_version={version};"
    ))
    .unwrap();
}

#[test]
fn v1_migration_is_transactional_and_bound_to_instance_and_audit() {
    let mut f = Fixture::new();
    rewind_schema(&f.db.connection, 1);
    f.db.connection
        .execute_batch(
            "DROP TABLE grant_deadlines; DROP TABLE file_operations;
             ALTER TABLE keys DROP COLUMN document_digest;",
        )
        .unwrap();
    let mut foreign = f.config.clone();
    foreign.instance_id = uuid();
    assert!(f.db.recovery(&foreign, now()).is_err());
    let version: i64 =
        f.db.connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
    assert_eq!(version, 1);
    f.db.connection.execute_batch("CREATE TRIGGER fail_migration BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%SCHEMA_MIGRATED%' BEGIN SELECT RAISE(ABORT,'injected migration failure'); END;").unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
    let version: i64 =
        f.db.connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
    assert_eq!(version, 1);
    f.db.connection
        .execute_batch("DROP TRIGGER fail_migration")
        .unwrap();
    f.db.recovery(&f.config, now()).unwrap();
    let version: i64 =
        f.db.connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
    assert_eq!(version, 4);
    verify_audit(&f.db.connection).unwrap();
}

fn changed_document(f: &Fixture, vault: &str, did: &str, doc: &Value) -> Value {
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(vault));
    let wrapped = crate::keystore::store::resolve(&layout, did, None).unwrap();
    let secret = crate::keystore::device::load(&layout).unwrap();
    let key = crate::keystore::unwrap::unlock(&wrapped, b"test-pass", &secret).unwrap();
    let mut unsigned = crate::did::lifecycle::strip_proof(doc).unwrap();
    unsigned["service"] = json!([{"id":format!("{did}#test"),"type":"TestService","serviceEndpoint":"https://example.com/updated"}]);
    let signed = crate::did::document::sign_document(&unsigned, &key, &wrapped.id.kid).unwrap();
    crate::did::document::verify_path_binding(did, &signed).unwrap();
    signed
}
#[test]
fn restart_rolls_forward_durable_intent_before_any_file_write() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, old) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let updated = changed_document(&f, &vault, &did, &old);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::InstallDocument {
                    vault_id: vault.clone(),
                    document: updated.clone(),
                },
            },
            now(),
        )
        .unwrap();
    f.db.commit_intent(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        old
    );
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        updated
    );
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        updated
    );
}
#[test]
fn pending_file_journal_cannot_substitute_an_unapproved_signed_document() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, old) = vault_fixture(&mut f);
    let updated = changed_document(&f, &vault, &did, &old);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::InstallDocument {
                    vault_id: vault.clone(),
                    document: old.clone(),
                },
            },
            now(),
        )
        .unwrap();
    f.db.commit_intent(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    let hash = hex(&Sha256::digest(
        serde_json_canonicalizer::to_vec(&updated).unwrap(),
    ));
    f.db.connection
        .execute(
            "UPDATE file_operations SET document=?1,after_digest=?2",
            params![serde_json::to_vec(&updated).unwrap(), hash],
        )
        .unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
}

#[test]
fn hot_and_recovery_roles_require_verified_document_relationships() {
    use anp::authentication::DidVerificationRelationship::{AssertionMethod, Authentication};
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, doc) = vault_fixture(&mut f);
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    let mut extras = Vec::new();
    for (fragment, relationship) in [
        ("not-a-role-name", Authentication),
        ("arbitrary-fragment", AssertionMethod),
    ] {
        let (_, extra) = crate::keystore::create::create_extra(
            &layout,
            &did,
            fragment,
            vec![relationship],
            "test",
            b"test-pass",
            crate::crypto::kdf::Argon2Config {
                m_cost: 1024,
                t_cost: 1,
                p_cost: 1,
            },
            crate::keystore::hardware::HardwareChoice::None,
        )
        .unwrap();
        extras.push(extra);
    }
    let root = crate::keystore::store::resolve(&layout, &did, None).unwrap();
    let secret = crate::keystore::device::load(&layout).unwrap();
    let key = crate::keystore::unwrap::unlock(&root, b"test-pass", &secret).unwrap();
    // Use the document's original subject/spec; only add explicit public keys.
    let mut unsigned = crate::did::lifecycle::strip_proof(&doc).unwrap();
    for extra in &extras {
        unsigned = crate::did::lifecycle::with_extra_key(
            &unsigned,
            &did,
            &key.verifying_key(),
            extra.clone(),
        )
        .unwrap();
    }
    let signed = crate::did::document::sign_document(&unsigned, &key, &root.id.kid).unwrap();
    crate::keystore::store::write_did_document(&layout, &did, &signed).unwrap();
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    for (fragment, role, wrong) in [
        ("not-a-role-name", KeyRole::Hot, KeyRole::Recovery),
        ("arbitrary-fragment", KeyRole::Recovery, KeyRole::Hot),
    ] {
        let record =
            f.db.catalog()
                .unwrap()
                .keys
                .into_iter()
                .find(|k| k.kid == format!("{did}#{fragment}"))
                .unwrap();
        assert!(f
            .db
            .prepare(
                1002,
                Change::Catalog {
                    change: CatalogChange::ConfirmRole {
                        key_id: record.key_id.clone(),
                        role: wrong
                    }
                },
                now()
            )
            .is_err());
        apply_change(
            &mut f,
            CatalogChange::ConfirmRole {
                key_id: record.key_id,
                role,
            },
        );
        f.db.check_key(&vault, &did, &record.kid).unwrap();
    }
}

#[test]
fn audit_failure_cannot_publish_a_file_or_leave_a_partial_catalog() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, doc) = vault_fixture(&mut f);
    let updated = changed_document(&f, &vault, &did, &doc);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::InstallDocument {
                    vault_id: vault.clone(),
                    document: updated,
                },
            },
            now(),
        )
        .unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_commit BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%OPERATION_COMMITTED%' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        doc
    );
    let count: i64 =
        f.db.connection
            .query_row("SELECT count(*) FROM file_operations", [], |r| r.get(0))
            .unwrap();
    assert_eq!(count, 0);
    let state: String =
        f.db.connection
            .query_row("SELECT state FROM vaults WHERE vault_id=?1", [vault], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(state, "active");
}

#[test]
fn unknown_persisted_role_is_refused_even_if_constraints_were_bypassed() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, _) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let record = f.db.catalog().unwrap().keys.remove(0);
    f.db.connection
        .execute_batch(
            "PRAGMA ignore_check_constraints=ON; UPDATE keys SET role='future_unknown_role';",
        )
        .unwrap();
    assert!(f.db.check_key(&vault, &did, &record.kid).is_err());
    assert!(f.db.catalog().is_err());
}

fn grant_fixture() -> (Fixture, String, String) {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, doc) = vault_fixture(&mut f);
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    let (_, extra) = crate::keystore::create::create_extra(
        &layout,
        &did,
        "http-hot",
        vec![anp::authentication::DidVerificationRelationship::Authentication],
        "test",
        b"test-pass",
        crate::crypto::kdf::Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        crate::keystore::hardware::HardwareChoice::None,
    )
    .unwrap();
    let root = crate::keystore::store::resolve(&layout, &did, None).unwrap();
    let secret = crate::keystore::device::load(&layout).unwrap();
    let key = crate::keystore::unwrap::unlock(&root, b"test-pass", &secret).unwrap();
    let unsigned = crate::did::lifecycle::strip_proof(&doc).unwrap();
    let unsigned =
        crate::did::lifecycle::with_extra_key(&unsigned, &did, &key.verifying_key(), extra)
            .unwrap();
    let signed = crate::did::document::sign_document(&unsigned, &key, &root.id.kid).unwrap();
    crate::keystore::store::write_did_document(&layout, &did, &signed).unwrap();
    apply_change(&mut f, CatalogChange::EnrollVault { vault_id: vault });
    let hot =
        f.db.catalog()
            .unwrap()
            .keys
            .into_iter()
            .find(|k| k.kid.ends_with("#http-hot"))
            .unwrap()
            .key_id;
    apply_change(
        &mut f,
        CatalogChange::ConfirmRole {
            key_id: hot.clone(),
            role: KeyRole::Hot,
        },
    );
    let policy = uuid();
    apply_change(
        &mut f,
        CatalogChange::PublishPolicy {
            policy_id: policy.clone(),
            version: 1,
            content: policy_value(),
        },
    );
    (f, hot, policy)
}
fn new_grant(f: &mut Fixture, key: &str, policy: &str) -> grants::Grant {
    let p =
        f.db.prepare(
            1002,
            Change::Grant {
                change: grants::GrantChange::Create {
                    principal_id: f.config.principals[0].principal_id.clone(),
                    key_id: key.into(),
                    policy_id: policy.into(),
                    policy_version: 1,
                    expiry: 1050,
                    max_uses: 2,
                },
            },
            now(),
        )
        .unwrap();
    let id = p.effect["effect"]["grant"]["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    f.db.grant_status(&f.config.principals[0].principal_id, &id, now())
        .unwrap()
}
fn canonical() -> crate::security::http::CanonicalHttpRequest {
    crate::security::http::CanonicalHttpRequest::new(crate::security::http::HttpRequest {
        method: "GET".into(),
        url: "https://service.example.com/v1/orders".into(),
        headers: Default::default(),
        body: crate::security::http::Body::Absent {},
        nonce: None,
    })
    .unwrap()
}
#[test]
fn grants_bind_principal_key_policy_and_revoke_without_consuming_quota() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    assert_eq!(g.grant_id.len(), 64);
    assert_eq!(
        f.db.authorized_keys(&g.principal_id, now()).unwrap().len(),
        1
    );
    let (_, selected) =
        f.db.authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
            .unwrap();
    assert_eq!(selected.key_id, key);
    let other =
        f.db.prepare(1002, Change::RegisterPrincipal { uid: 1006 }, now())
            .unwrap();
    f.db.commit(1002, &other.operation_id, &other.digest, now())
        .unwrap();
    let other = f.db.principal(1006).unwrap().unwrap().principal_id;
    assert!(f.db.grant_status(&other, &g.grant_id, now()).is_err());
    assert!(f
        .db
        .authorize_http(&other, &g.grant_id, &canonical(), now())
        .is_err());
    assert!(f.db.authorized_keys(&other, now()).unwrap().is_empty());
    assert_eq!(
        f.db.grant_status(&g.principal_id, &g.grant_id, now())
            .unwrap()
            .used_uses,
        0
    );
    let p =
        f.db.prepare(
            1002,
            Change::Grant {
                change: grants::GrantChange::Revoke {
                    grant_id: g.grant_id.clone(),
                },
            },
            now(),
        )
        .unwrap();
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    assert!(f
        .db
        .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
        .is_err());
    assert!(f
        .db
        .authorized_keys(&g.principal_id, now())
        .unwrap()
        .is_empty());
    verify_audit(&f.db.connection).unwrap();
}
#[test]
fn grant_deadlines_survive_wall_rollback_and_never_revive() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let late = Time {
        wall: 900,
        monotonic_ms: 60_000,
    };
    assert_eq!(
        f.db.grant_status(&g.principal_id, &g.grant_id, late)
            .unwrap()
            .state,
        "expired"
    );
    assert!(f
        .db
        .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
        .is_err());
    let g = new_grant(&mut f, &key, &policy);
    assert_eq!(
        f.db.grant_status(
            &g.principal_id,
            &g.grant_id,
            Time {
                wall: 1050,
                monotonic_ms: 10001
            }
        )
        .unwrap()
        .state,
        "expired"
    );
    let g = new_grant(&mut f, &key, &policy);
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        f.db.grant_status(&g.principal_id, &g.grant_id, now())
            .unwrap()
            .state,
        "revoked_restart"
    );
    assert!(f
        .db
        .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
        .is_err());
}
#[test]
fn grants_reject_nonhot_keys_limits_stale_role_and_policy_mismatch() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    for record in f.db.catalog().unwrap().keys {
        if record.key_id == key {
            continue;
        }
        assert!(f
            .db
            .prepare(
                1002,
                Change::Grant {
                    change: grants::GrantChange::Create {
                        principal_id: g.principal_id.clone(),
                        key_id: record.key_id,
                        policy_id: policy.clone(),
                        policy_version: 1,
                        expiry: 1050,
                        max_uses: 1
                    }
                },
                now()
            )
            .is_err());
    }
    for (expiry, uses) in [(1000, 1), (999999, 1), (1050, 0), (1050, u32::MAX)] {
        assert!(f
            .db
            .prepare(
                1002,
                Change::Grant {
                    change: grants::GrantChange::Create {
                        principal_id: g.principal_id.clone(),
                        key_id: key.clone(),
                        policy_id: policy.clone(),
                        policy_version: 1,
                        expiry,
                        max_uses: uses
                    }
                },
                now()
            )
            .is_err());
    }
    for (method, url, body) in [
        (
            "POST",
            "https://service.example.com/v1/orders",
            crate::security::http::Body::Absent {},
        ),
        (
            "GET",
            "https://evil.com/test",
            crate::security::http::Body::Absent {},
        ),
        (
            "GET",
            "https://service.example.com/other",
            crate::security::http::Body::Absent {},
        ),
        (
            "GET",
            "https://service.example.com/v1/orders?a=1",
            crate::security::http::Body::Absent {},
        ),
        (
            "GET",
            "https://service.example.com/v1/orders",
            crate::security::http::Body::Present { bytes: vec![1] },
        ),
    ] {
        let req =
            crate::security::http::CanonicalHttpRequest::new(crate::security::http::HttpRequest {
                method: method.into(),
                url: url.into(),
                headers: Default::default(),
                body,
                nonce: None,
            })
            .unwrap();
        assert!(f
            .db
            .authorize_http(&g.principal_id, &g.grant_id, &req, now())
            .is_err());
    }
    f.db.connection
        .execute("UPDATE keys SET role='root' WHERE key_id=?1", [key])
        .unwrap();
    assert!(f
        .db
        .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
        .is_err());
}
#[test]
fn grant_creation_audit_failure_is_atomic() {
    let (mut f, key, policy) = grant_fixture();
    let p =
        f.db.prepare(
            1002,
            Change::Grant {
                change: grants::GrantChange::Create {
                    principal_id: f.config.principals[0].principal_id.clone(),
                    key_id: key,
                    policy_id: policy,
                    policy_version: 1,
                    expiry: 1050,
                    max_uses: 1,
                },
            },
            now(),
        )
        .unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_grant BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert_eq!(
        f.db.connection
            .query_row("SELECT COUNT(*) FROM grants", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn bounded_body_and_exact_query_cannot_be_omitted_or_reinterpreted() {
    let (mut f, key, policy) = grant_fixture();
    let mut content = policy_value();
    content["methods"] = json!(["POST"]);
    content["body"] = json!({"mode":"bounded","max_bytes":3});
    content["query"] = json!({"mode":"exact","value":"a=1&b=2"});
    apply_change(
        &mut f,
        catalog::CatalogChange::PublishPolicy {
            policy_id: policy.clone(),
            version: 2,
            content,
        },
    );
    let p =
        f.db.prepare(
            1002,
            Change::Grant {
                change: grants::GrantChange::Create {
                    principal_id: f.config.principals[0].principal_id.clone(),
                    key_id: key,
                    policy_id: policy,
                    policy_version: 2,
                    expiry: 1050,
                    max_uses: 2,
                },
            },
            now(),
        )
        .unwrap();
    let id = p.effect["effect"]["grant"]["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    let principal = f.config.principals[0].principal_id.clone();
    for (body, query, allowed) in [
        (crate::security::http::Body::Absent {}, "a=1&b=2", false),
        (
            crate::security::http::Body::Present { bytes: vec![] },
            "a=1&b=2",
            true,
        ),
        (
            crate::security::http::Body::Present {
                bytes: vec![1, 2, 3],
            },
            "a=1&b=2",
            true,
        ),
        (
            crate::security::http::Body::Present {
                bytes: vec![1, 2, 3, 4],
            },
            "a=1&b=2",
            false,
        ),
        (
            crate::security::http::Body::Present { bytes: vec![1] },
            "b=2&a=1",
            false,
        ),
    ] {
        let req =
            crate::security::http::CanonicalHttpRequest::new(crate::security::http::HttpRequest {
                method: "POST".into(),
                url: format!("https://service.example.com/v1/orders?{query}"),
                headers: Default::default(),
                body,
                nonce: None,
            })
            .unwrap();
        assert_eq!(
            f.db.authorize_http(&principal, &id, &req, now()).is_ok(),
            allowed
        );
        if allowed {
            assert!(
                crate::sign::rfc9421::required_components(req.signing_request())
                    .contains(&"content-digest".to_owned())
            );
        }
    }
}
#[test]
fn live_principal_and_envelope_checks_cannot_be_cached_by_grant() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let k =
        f.db.catalog()
            .unwrap()
            .keys
            .into_iter()
            .find(|k| k.key_id == key)
            .unwrap();
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&k.vault_id));
    let mut w = crate::keystore::store::resolve(&layout, &k.did, Some("http-hot")).unwrap();
    w.label = "replaced".into();
    crate::keystore::store::write(&layout, &w).unwrap();
    assert!(f
        .db
        .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
        .is_err());
    let p = f.disable();
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    assert!(f.db.authorized_keys(&g.principal_id, now()).is_err());
    assert!(f
        .db
        .grant_status(&g.principal_id, &g.grant_id, now())
        .is_err());
}
#[test]
fn prepared_grant_cannot_extend_deadline_at_commit_or_bypass_exhaustion() {
    let (mut f, key, policy) = grant_fixture();
    let p =
        f.db.prepare(
            1002,
            Change::Grant {
                change: grants::GrantChange::Create {
                    principal_id: f.config.principals[0].principal_id.clone(),
                    key_id: key.clone(),
                    policy_id: policy.clone(),
                    policy_version: 1,
                    expiry: 1050,
                    max_uses: 1,
                },
            },
            now(),
        )
        .unwrap();
    assert!(f
        .db
        .commit(
            1002,
            &p.operation_id,
            &p.digest,
            Time {
                wall: 1001,
                monotonic_ms: 60000
            }
        )
        .is_err());
    let g = new_grant(&mut f, &key, &policy);
    f.db.connection
        .execute(
            "UPDATE grants SET used_uses=max_uses WHERE grant_id=?1",
            [&g.grant_id],
        )
        .unwrap();
    assert!(f
        .db
        .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
        .unwrap_err()
        .to_string()
        .contains("GRANT_EXHAUSTED"));
    assert!(f
        .db
        .authorized_keys(&g.principal_id, now())
        .unwrap()
        .is_empty());
}
#[test]
fn v2_to_v3_migration_is_atomic_and_invalidates_old_grants() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    rewind_schema(&f.db.connection, 2);
    f.db.connection
        .execute_batch("DROP TABLE grant_deadlines;")
        .unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_migration BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%SCHEMA_MIGRATED%' BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
    assert_eq!(
        f.db.connection
            .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    f.db.connection
        .execute_batch("DROP TRIGGER fail_migration")
        .unwrap();
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        f.db.grant_status(&g.principal_id, &g.grant_id, now())
            .unwrap()
            .state,
        "revoked_restart"
    );
    verify_audit(&f.db.connection).unwrap();
}

fn origin_policy(f: &mut Fixture, max_renewals: u32) -> String {
    let id = uuid();
    apply_change(
        f,
        catalog::CatalogChange::PublishPolicy {
            policy_id: id.clone(),
            version: 1,
            content: json!({"schema_version":2,"name":"im-origin","purpose":"origin-proof",
              "limits":{"max_duration_seconds":900,"max_uses":100000,"max_lifetime_seconds":86400,"max_renewals":max_renewals},
              "content":{"methods":["direct.send"],"target_kinds":["agent"],"body":{"mode":"bounded","max_bytes":8192}}}),
        },
    );
    id
}

fn origin_proof() -> crate::security::origin::OriginProof {
    crate::security::origin::OriginProofRequest {
        method: "direct.send".into(),
        meta: json!({"profile":"anp.direct.base.v1","target":{"kind":"agent","did":"did:wba:example.com:alice"}}),
        body: json!({"text":"hi"}),
        expires: Some(1_100),
        nonce: Some("n-1".into()),
    }
    .validate(1_000)
    .unwrap()
}

fn new_session(f: &mut Fixture, key: &str, policy: &str, expiry: i64) -> grants::Grant {
    let principal = f.config.principals[0].principal_id.clone();
    let p = f
        .db
        .prepare(
            1002,
            Change::Grant {
                change: grants::GrantChange::CreateSession {
                    principal_id: principal.clone(),
                    key_id: key.into(),
                    policy_id: policy.into(),
                    policy_version: 1,
                    expiry,
                    max_uses: 10_000,
                },
            },
            now(),
        )
        .unwrap();
    let id = p.effect["effect"]["grant"]["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    f.db.grant_status(&principal, &id, now()).unwrap()
}

#[test]
fn session_grants_carry_their_operation_and_authorize_only_that_purpose() {
    let (mut f, key, _) = grant_fixture();
    let policy = origin_policy(&mut f, 16);
    let g = new_session(&mut f, &key, &policy, 1_900);
    assert_eq!(g.kind, "session");
    assert_eq!(g.max_renewals, 16);
    assert_eq!(g.created_at, 1_000);
    let operations: Vec<String> = {
        let mut s = f
            .db
            .connection
            .prepare("SELECT operation FROM grant_operations WHERE grant_id=?1")
            .unwrap();
        s.query_map([&g.grant_id], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    };
    assert_eq!(operations, ["SIGN_ORIGIN_PROOF"]);
    let (_, selected) = f
        .db
        .authorize_origin(&g.principal_id, &g.grant_id, &origin_proof(), now())
        .unwrap();
    assert_eq!(selected.key_id, key);
    // 同一个 grant 不能拿来签 HTTP:操作集里只有它被建出来的那一个。
    assert!(f
        .db
        .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
        .is_err());
    verify_audit(&f.db.connection).unwrap();
}

#[test]
fn session_renewal_extends_to_the_nearest_ceiling_and_is_audited() {
    let (mut f, key, _) = grant_fixture();
    let policy = origin_policy(&mut f, 16);
    let g = new_session(&mut f, &key, &policy, 1_900);
    let later = Time {
        wall: 1_500,
        monotonic_ms: 500_000,
    };
    // 请求 10000,实际给到 now+900。
    let renewed = f
        .db
        .renew_grant(&g.principal_id, &g.grant_id, 10_000, later)
        .unwrap();
    assert_eq!((renewed.expiry, renewed.renewals), (2_400, 1));
    // 不能原地踏步,也不能把到期日往下压。
    assert!(matches!(
        f.db.renew_grant(&g.principal_id, &g.grant_id, 2_400, later),
        Err(KeydError::Misuse(c)) if c == "GRANT_INVALID"
    ));
    let renewed: i64 = f
        .db
        .connection
        .query_row(
            "SELECT monotonic_deadline FROM grant_deadlines WHERE grant_id=?1",
            [&g.grant_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(renewed, 500_000 + 900_000);
    let events: Vec<String> = {
        let mut s = f
            .db
            .connection
            .prepare("SELECT json_extract(CAST(event_data AS TEXT),'$.event') FROM audit_events")
            .unwrap();
        s.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    };
    assert!(events.iter().any(|e| e == "GRANT_CREATED"));
    assert!(events.iter().any(|e| e == "GRANT_RENEWED"));
    verify_audit(&f.db.connection).unwrap();
}

#[test]
fn renewal_stops_at_the_absolute_lifetime_and_at_the_renewal_budget() {
    let (mut f, key, _) = grant_fixture();
    let policy = origin_policy(&mut f, 1);
    let g = new_session(&mut f, &key, &policy, 1_900);
    // 只给一次续期预算。
    let once = Time {
        wall: 1_500,
        monotonic_ms: 500_000,
    };
    assert!(f
        .db
        .renew_grant(&g.principal_id, &g.grant_id, 2_400, once)
        .is_ok());
    let again = Time {
        wall: 2_000,
        monotonic_ms: 900_000,
    };
    assert!(matches!(
        f.db.renew_grant(&g.principal_id, &g.grant_id, 3_000, again),
        Err(KeydError::Misuse(c)) if c == "GRANT_RENEWALS_EXHAUSTED"
    ));
    // 绝对寿命天花板:created_at+86400,不会被 now+900 顶上去。
    f.db.connection
        .execute(
            "UPDATE grants SET expiry=87000,renewals=0 WHERE grant_id=?1",
            [&g.grant_id],
        )
        .unwrap();
    f.db.connection
        .execute(
            "UPDATE grant_deadlines SET monotonic_deadline=87400000 WHERE grant_id=?1",
            [&g.grant_id],
        )
        .unwrap();
    let near_end = Time {
        wall: 86_900,
        monotonic_ms: 86_900_000,
    };
    let renewed = f
        .db
        .renew_grant(&g.principal_id, &g.grant_id, 200_000, near_end)
        .unwrap();
    assert_eq!(renewed.expiry, 87_400);
    verify_audit(&f.db.connection).unwrap();
}

#[test]
fn a_one_shot_grant_cannot_be_renewed() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    assert_eq!(g.kind, "request");
    assert!(matches!(
        f.db.renew_grant(&g.principal_id, &g.grant_id, 5_000, now()),
        Err(KeydError::Misuse(c)) if c == "GRANT_INVALID"
    ));
}

#[test]
fn origin_reservations_deduplicate_and_never_share_an_id_with_another_purpose() {
    let (mut f, key, _) = grant_fixture();
    let policy = origin_policy(&mut f, 16);
    let g = new_session(&mut f, &key, &policy, 1_900);
    let proof = origin_proof();
    let id = uuid();
    let principal = g.principal_id.clone();
    assert!(matches!(
        f.db.reserve_origin(&principal, &g.grant_id, &id, &proof, now())
            .unwrap(),
        requests::Reservation::New { .. }
    ));
    // 同一条事实同一个 id:命中已有预留,不再扣配额。
    assert!(matches!(
        f.db.reserve_origin(&principal, &g.grant_id, &id, &proof, now())
            .unwrap(),
        requests::Reservation::Existing(_)
    ));
    let uses: i64 = f
        .db
        .connection
        .query_row(
            "SELECT used_uses FROM grants WHERE grant_id=?1",
            [&g.grant_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(uses, 1);
    // 同一个 id 换个用途是冲突,不是缓存命中 —— 缓存不跨操作复用。
    assert!(matches!(
        f.db.reserve_http(&principal, &g.grant_id, &id, &canonical(), now()),
        Err(KeydError::Misuse(c)) if c == "REQUEST_ID_CONFLICT"
    ));
    f.db.complete_origin(
        &principal,
        &id,
        &json!({"request_id":id}),
        (1_100, 1_100_000),
        "aa",
        json!({"method":"direct.send"}),
        now(),
    )
    .unwrap();
    let status = f.db.request_status(&principal, &id, now()).unwrap();
    assert_eq!(status.state, "completed");
    assert_eq!(status.result.unwrap()["request_id"], json!(id));
    let reserved: String = f
        .db
        .connection
        .query_row(
            "SELECT json_extract(CAST(event_data AS TEXT),'$.purpose') FROM audit_events WHERE json_extract(CAST(event_data AS TEXT),'$.event')='SIGN_RESERVED'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(reserved, "origin-proof");
    let completed: String = f
        .db
        .connection
        .query_row(
            "SELECT json_extract(CAST(event_data AS TEXT),'$.origin.method') FROM audit_events WHERE json_extract(CAST(event_data AS TEXT),'$.event')='SIGN_COMPLETED'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(completed, "direct.send");
    verify_audit(&f.db.connection).unwrap();
}

#[test]
fn missing_monotonic_deadline_stops_authorization() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    f.db.connection
        .execute(
            "DELETE FROM grant_deadlines WHERE grant_id=?1",
            [&g.grant_id],
        )
        .unwrap();
    assert!(f
        .db
        .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
        .is_err());
}
#[test]
fn every_nonhot_role_is_forbidden_for_grants_and_data() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    for role in ["root", "recovery", "unclassified", "challenge"] {
        f.db.connection
            .execute(
                "UPDATE keys SET role=?1 WHERE key_id=?2",
                params![role, key],
            )
            .unwrap();
        assert!(f
            .db
            .authorize_http(&g.principal_id, &g.grant_id, &canonical(), now())
            .is_err());
        assert!(f
            .db
            .prepare(
                1002,
                Change::Grant {
                    change: grants::GrantChange::Create {
                        principal_id: g.principal_id.clone(),
                        key_id: key.clone(),
                        policy_id: policy.clone(),
                        policy_version: 1,
                        expiry: 1050,
                        max_uses: 1
                    }
                },
                now()
            )
            .is_err());
    }
}

#[test]
fn transaction_reservations_are_idempotent_and_never_refund() {
    use requests::Reservation;
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let id = uuid();
    assert!(matches!(
        f.db.reserve_http(&g.principal_id, &g.grant_id, &id, &canonical(), now())
            .unwrap(),
        Reservation::New { .. }
    ));
    assert!(matches!(
        f.db.reserve_http(&g.principal_id, &g.grant_id, &id, &canonical(), now())
            .unwrap(),
        Reservation::Existing(_)
    ));
    f.db.complete_http(
        &g.principal_id,
        &id,
        &json!({"headers":{"Signature":"temporary"}}),
        (1040, 45000),
        "digest",
        now(),
    )
    .unwrap();
    let original =
        f.db.request_status(&g.principal_id, &id, now())
            .unwrap()
            .result
            .unwrap();
    f.db.fail_reserved(&g.principal_id, &id, false, now())
        .unwrap_err();
    let second = uuid();
    f.db.reserve_http(&g.principal_id, &g.grant_id, &second, &canonical(), now())
        .unwrap();
    f.db.fail_reserved(&g.principal_id, &second, false, now())
        .unwrap();
    assert!(f
        .db
        .reserve_http(&g.principal_id, &g.grant_id, &uuid(), &canonical(), now())
        .is_err());
    let cached = f.db.request_status(&g.principal_id, &id, now()).unwrap();
    assert_eq!(cached.result.unwrap(), original);
    assert_eq!(
        f.db.grant_status(&g.principal_id, &g.grant_id, now())
            .unwrap()
            .used_uses,
        2
    );
    let other = new_grant(&mut f, &key, &policy);
    assert!(
        matches!(f.db.reserve_http(&g.principal_id,&other.grant_id,&id,&canonical(),now()),Err(KeydError::Misuse(c)) if c=="REQUEST_ID_CONFLICT")
    );
    let expired = Time {
        wall: 900,
        monotonic_ms: 45000,
    };
    assert!(f
        .db
        .request_status(&g.principal_id, &id, expired)
        .unwrap()
        .result
        .is_none());
    assert!(f
        .db
        .request_status(&g.principal_id, &id, now())
        .unwrap()
        .result
        .is_none());
    verify_audit(&f.db.connection).unwrap();
}
#[test]
fn reservation_and_result_audit_failures_are_atomic() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let id = uuid();
    f.db.connection.execute_batch("CREATE TRIGGER fail_event BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();
    assert!(f
        .db
        .reserve_http(&g.principal_id, &g.grant_id, &id, &canonical(), now())
        .is_err());
    assert_eq!(
        grants::get(&f.db.connection, &g.grant_id)
            .unwrap()
            .unwrap()
            .used_uses,
        0
    );
    f.db.connection
        .execute_batch("DROP TRIGGER fail_event")
        .unwrap();
    f.db.reserve_http(&g.principal_id, &g.grant_id, &id, &canonical(), now())
        .unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_event BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();
    assert!(f
        .db
        .complete_http(
            &g.principal_id,
            &id,
            &json!({"signature":"undelivered"}),
            (1040, 45000),
            "digest",
            now()
        )
        .is_err());
    f.db.connection
        .execute_batch("DROP TRIGGER fail_event")
        .unwrap();
    let status = f.db.request_status(&g.principal_id, &id, now()).unwrap();
    assert_eq!(status.state, "reserved");
    assert!(status.result.is_none());
    f.db.recovery(&f.config, now()).unwrap();
    let status = f.db.request_status(&g.principal_id, &id, now()).unwrap();
    assert_eq!(status.state, "outcome_unknown");
    assert!(status.result.is_none());
    assert_eq!(
        grants::get(&f.db.connection, &g.grant_id)
            .unwrap()
            .unwrap()
            .used_uses,
        1
    );
}
#[test]
fn revocation_and_restart_suppress_completed_results() {
    for restart in [false, true] {
        let (mut f, key, policy) = grant_fixture();
        let g = new_grant(&mut f, &key, &policy);
        let id = uuid();
        f.db.reserve_http(&g.principal_id, &g.grant_id, &id, &canonical(), now())
            .unwrap();
        f.db.complete_http(
            &g.principal_id,
            &id,
            &json!({"signature":"cached"}),
            (1040, 45000),
            "digest",
            now(),
        )
        .unwrap();
        if restart {
            f.db.recovery(&f.config, now()).unwrap();
        } else {
            let p =
                f.db.prepare(
                    1002,
                    Change::Grant {
                        change: grants::GrantChange::Revoke {
                            grant_id: g.grant_id.clone(),
                        },
                    },
                    now(),
                )
                .unwrap();
            f.db.commit(1002, &p.operation_id, &p.digest, now())
                .unwrap();
        }
        assert!(f
            .db
            .request_status(&g.principal_id, &id, now())
            .unwrap()
            .result
            .is_none());
        assert!(f.db.request_status(&uuid(), &id, now()).is_err());
        verify_audit(&f.db.connection).unwrap();
    }
}

struct FixedClock;
impl clock::Clock for FixedClock {
    fn now(&self) -> Result<Time> {
        Ok(now())
    }
}
fn fake_signed() -> crate::sign::rfc9421::Signed {
    crate::sign::rfc9421::Signed {
        created_at: Some(1000),
        expires_at: Some(1040),
        headers: std::collections::BTreeMap::from([("Signature".into(), "test-result".into())]),
        covered: vec!["@method".into()],
        signature_base_digest: [7; 32],
    }
}
#[test]
fn executor_calls_backend_once_and_never_on_reservation_failure() {
    use crate::security::executor::execute;
    use std::cell::Cell;
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let id = uuid();
    let calls = Cell::new(0);
    f.db.connection.execute_batch("CREATE TRIGGER no_reserve BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%SIGN_RESERVED%' BEGIN SELECT RAISE(ABORT,'reserve failure'); END;").unwrap();
    assert!(execute(
        &mut f.db,
        &g.principal_id,
        &g.grant_id,
        &id,
        &canonical(),
        &FixedClock,
        |_, _, _| {
            calls.set(calls.get() + 1);
            Ok(fake_signed())
        }
    )
    .is_err());
    assert_eq!(calls.get(), 0);
    f.db.connection
        .execute_batch("DROP TRIGGER no_reserve")
        .unwrap();
    let first = execute(
        &mut f.db,
        &g.principal_id,
        &g.grant_id,
        &id,
        &canonical(),
        &FixedClock,
        |_, _, _| {
            calls.set(calls.get() + 1);
            Ok(fake_signed())
        },
    )
    .unwrap();
    let cached = execute(
        &mut f.db,
        &g.principal_id,
        &g.grant_id,
        &id,
        &canonical(),
        &FixedClock,
        |_, _, _| panic!("retry signed twice"),
    )
    .unwrap();
    assert_eq!(first.result, cached.result);
    assert_eq!(calls.get(), 1);
    f.db.connection.execute_batch("CREATE TRIGGER no_complete BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%SIGN_COMPLETED%' BEGIN SELECT RAISE(ABORT,'complete failure'); END;").unwrap();
    let id = uuid();
    assert!(execute(
        &mut f.db,
        &g.principal_id,
        &g.grant_id,
        &id,
        &canonical(),
        &FixedClock,
        |_, _, _| Ok(fake_signed())
    )
    .is_err());
    f.db.connection
        .execute_batch("DROP TRIGGER no_complete")
        .unwrap();
    assert!(execute(
        &mut f.db,
        &g.principal_id,
        &g.grant_id,
        &id,
        &canonical(),
        &FixedClock,
        |_, _, _| panic!("uncertain result retried")
    )
    .unwrap()
    .result
    .is_none());
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        f.db.request_status(&g.principal_id, &id, now())
            .unwrap()
            .state,
        "outcome_unknown"
    );
}
#[test]
fn executor_expiry_backend_failure_and_crash_keep_consumed_quota() {
    use crate::security::executor::execute;
    use std::cell::Cell;
    struct AdvancingClock(Cell<u8>);
    impl clock::Clock for AdvancingClock {
        fn now(&self) -> Result<Time> {
            let n = self.0.get();
            self.0.set(n + 1);
            Ok(if n == 0 {
                now()
            } else {
                Time {
                    wall: 1060,
                    monotonic_ms: 61000,
                }
            })
        }
    }
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let id = uuid();
    assert!(execute(
        &mut f.db,
        &g.principal_id,
        &g.grant_id,
        &id,
        &canonical(),
        &AdvancingClock(Cell::new(0)),
        |_, _, _| panic!("expired after reserve")
    )
    .is_err());
    assert_eq!(
        f.db.request_status(&g.principal_id, &id, now())
            .unwrap()
            .state,
        "failed_reserved"
    );
    let id = uuid();
    assert!(execute(
        &mut f.db,
        &g.principal_id,
        &g.grant_id,
        &id,
        &canonical(),
        &FixedClock,
        |_, _, _| Err(KeydError::Upstream("after signing".into()))
    )
    .is_err());
    assert_eq!(
        f.db.request_status(&g.principal_id, &id, now())
            .unwrap()
            .state,
        "outcome_unknown"
    );
    assert_eq!(
        f.db.grant_status(&g.principal_id, &g.grant_id, now())
            .unwrap()
            .used_uses,
        2
    );
    let g = new_grant(&mut f, &key, &policy);
    let id = uuid();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute(
            &mut f.db,
            &g.principal_id,
            &g.grant_id,
            &id,
            &canonical(),
            &FixedClock,
            |_, _, _| panic!("simulated crash after reserve"),
        )
    }));
    assert!(outcome.is_err());
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        f.db.request_status(&g.principal_id, &id, now())
            .unwrap()
            .state,
        "outcome_unknown"
    );
}
#[test]
fn audit_projection_is_repeatable_read_only_and_failure_preserves_old_export() {
    let f = Fixture::new();
    let before =
        f.db.connection
            .query_row("SELECT count(*) FROM audit_events", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap();
    assert_eq!(projection::export(&f.dir).unwrap(), before);
    let path = f.dir.join("audit-export/events.jsonl");
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(projection::export(&f.dir).unwrap(), before);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let events: Vec<Value> = std::str::from_utf8(&bytes)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(events.len(), before as usize);
    assert_eq!(events[0]["seq"], 1);
    f.db.connection
        .execute(
            "UPDATE audit_events SET event_digest='invalid' WHERE seq=1",
            [],
        )
        .unwrap();
    assert!(projection::export(&f.dir).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}
#[test]
fn sqlite_full_cannot_reserve_without_durable_audit() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let id = uuid();
    let pages: i64 =
        f.db.connection
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
    f.db.connection.execute_batch(&format!("PRAGMA max_page_count={pages}; CREATE TRIGGER disk_full BEFORE INSERT ON requests BEGIN INSERT INTO audit_events VALUES(999999,'full','full',zeroblob(2097152)); END;")).unwrap();
    assert!(f
        .db
        .reserve_http(&g.principal_id, &g.grant_id, &id, &canonical(), now())
        .is_err());
    assert_eq!(
        grants::get(&f.db.connection, &g.grant_id)
            .unwrap()
            .unwrap()
            .used_uses,
        0
    );
    assert_eq!(
        f.db.connection
            .query_row("SELECT count(*) FROM requests", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    verify_audit(&f.db.connection).unwrap();
}

#[test]
fn scheduled_result_retention_preserves_tombstones_and_audit_atomicity() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let id = uuid();
    f.db.reserve_http(&g.principal_id, &g.grant_id, &id, &canonical(), now())
        .unwrap();
    f.db.complete_http(
        &g.principal_id,
        &id,
        &json!({"signature":"retained"}),
        (1040, 45000),
        "digest",
        now(),
    )
    .unwrap();
    assert_eq!(f.db.prune_results(now()).unwrap(), 0);
    f.db.connection.execute_batch("CREATE TRIGGER fail_prune BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%SIGN_RESULTS_PRUNED%' BEGIN SELECT RAISE(ABORT,'fail'); END").unwrap();
    let late = Time {
        wall: 900,
        monotonic_ms: 45000,
    };
    assert!(f.db.prune_results(late).is_err());
    let retained: bool =
        f.db.connection
            .query_row(
                "SELECT result IS NOT NULL FROM requests WHERE request_id=?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
    assert!(retained);
    f.db.connection
        .execute_batch("DROP TRIGGER fail_prune")
        .unwrap();
    assert_eq!(f.db.prune_results(late).unwrap(), 1);
    assert_eq!(f.db.prune_results(late).unwrap(), 0);
    assert!(f
        .db
        .request_status(&g.principal_id, &id, now())
        .unwrap()
        .result
        .is_none());
    assert_eq!(
        grants::get(&f.db.connection, &g.grant_id)
            .unwrap()
            .unwrap()
            .used_uses,
        1
    );
    verify_audit(&f.db.connection).unwrap();
}
#[test]
fn legacy_audit_is_verified_and_bound_to_prepared_enrollment() {
    use catalog::CatalogChange;
    let mut f = Fixture::new();
    let (vault, _, _) = vault_fixture(&mut f);
    let change = Change::Catalog {
        change: CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    };
    let p = f.db.prepare(1002, change, now()).unwrap();
    let audit = f.dir.join("vaults").join(&vault).join("audit");
    let original = crate::audit::log::legacy_summary(&audit).unwrap();
    assert!(original["files_digest"].as_str().is_some());
    let mut history = crate::audit::AuditLog::open(&audit).unwrap();
    history
        .append(&crate::audit::Event::Locked {
            uid: 1001,
            did: None,
            dropped: 0,
        })
        .unwrap();
    drop(history);
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    verify_audit(&f.db.connection).unwrap();
}

#[test]
fn cached_signature_uses_actual_short_window_after_wall_clock_jump() {
    let (mut f, key, policy) = grant_fixture();
    let g = new_grant(&mut f, &key, &policy);
    let id = uuid();
    crate::security::executor::execute(
        &mut f.db,
        &g.principal_id,
        &g.grant_id,
        &id,
        &canonical(),
        &FixedClock,
        |_, _, _| {
            let mut signed = fake_signed();
            signed.created_at = Some(1040);
            signed.expires_at = Some(1041);
            Ok(signed)
        },
    )
    .unwrap();
    let late = Time {
        wall: 1000,
        monotonic_ms: now().monotonic_ms + 1000,
    };
    assert!(f
        .db
        .request_status(&g.principal_id, &id, late)
        .unwrap()
        .result
        .is_none());
}

#[test]
fn migration_inspection_rejects_links_and_missing_or_substituted_documents() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let mut f = Fixture::new();
    let (vault, did, _) = vault_fixture(&mut f);
    let path = f.dir.join("vaults").join(vault);
    let report = crate::security::migration::inspect(&path, false).unwrap();
    assert_eq!(report["recovery_verified"], false);
    assert_eq!(report["keys"][0]["role"], "unclassified");
    let layout = crate::keystore::layout::KeydLayout::at(path.clone());
    let document = layout.did_path(&did);
    let bytes = std::fs::read(&document).unwrap();
    std::fs::remove_file(&document).unwrap();
    assert!(crate::security::migration::inspect(&path, false).is_err());
    let other = f.dir.join("other.json");
    std::fs::write(&other, bytes).unwrap();
    symlink(&other, &document).unwrap();
    assert!(crate::security::migration::inspect(&path, false).is_err());
    std::fs::remove_file(&document).unwrap();
    std::fs::rename(other, document).unwrap();
    std::fs::set_permissions(
        path.join("device.secret"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(crate::security::migration::inspect(&path, false).is_err());
}

#[test]
fn registration_is_exact_root_only_single_use_and_commits_audit_before_release() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, _) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let root = f.db.catalog().unwrap().keys.remove(0);
    let change = |challenge: &str| Change::RegistrationChallenge {
        key_id: root.key_id.clone(),
        origin: "https://example.com".into(),
        challenge: challenge.into(),
    };
    let challenge = "0123456789abcdef0123456789abcdef";
    assert!(f.db.prepare(1002, change(challenge), now()).is_err());
    apply_change(
        &mut f,
        CatalogChange::ConfirmRole {
            key_id: root.key_id.clone(),
            role: KeyRole::Root,
        },
    );
    for bad in ["", "0123456789abcdef", &"a".repeat(64), &"A".repeat(32)] {
        assert!(f.db.prepare(1002, change(bad), now()).is_err());
    }
    let p = f.db.prepare(1002, change(challenge), now()).unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f
        .db
        .complete_secret_operation(1003, &p.operation_id, &p.digest, now(), "test-pass")
        .is_err());
    assert!(f
        .db
        .complete_secret_operation(1002, &p.operation_id, &p.digest, now(), "wrong")
        .is_err());
    let result =
        f.db.complete_secret_operation(1002, &p.operation_id, &p.digest, now(), "test-pass")
            .unwrap();
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(result["challenge_signature"].as_str().unwrap())
        .unwrap();
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    let wrapped = crate::keystore::store::resolve(&layout, &did, None).unwrap();
    let key = crate::keystore::unwrap::unlock(
        &wrapped,
        b"test-pass",
        &crate::keystore::device::load(&layout).unwrap(),
    )
    .unwrap();
    assert!(key.verify(challenge.as_bytes(), &bytes.try_into().unwrap()));
    assert!(f
        .db
        .complete_secret_operation(1002, &p.operation_id, &p.digest, now(), "test-pass")
        .is_err());
    let p = f.db.prepare(1002, change(challenge), now()).unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_registration_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    assert!(f
        .db
        .complete_secret_operation(1002, &p.operation_id, &p.digest, now(), "test-pass")
        .is_err());
    assert_eq!(
        f.db.connection
            .query_row(
                "SELECT state FROM admin_operations WHERE operation_id=?",
                [p.operation_id],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
        "prepared"
    );
}

#[test]
fn trusted_hot_rotation_retires_old_key_revokes_grants_and_recovers_approved_document() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, doc) = vault_fixture(&mut f);
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    let root_envelope = crate::keystore::store::resolve(&layout, &did, None).unwrap();
    let root_signer = crate::keystore::unwrap::unlock(
        &root_envelope,
        b"test-pass",
        &crate::keystore::device::load(&layout).unwrap(),
    )
    .unwrap();
    let mut unsigned = crate::did::lifecycle::strip_proof(&doc).unwrap();
    for fragment in ["hot-old", "hot-next"] {
        let (_, extra) = crate::keystore::create::create_extra(
            &layout,
            &did,
            fragment,
            vec![anp::authentication::DidVerificationRelationship::Authentication],
            "test",
            b"test-pass",
            crate::crypto::kdf::Argon2Config {
                m_cost: 1024,
                t_cost: 1,
                p_cost: 1,
            },
            crate::keystore::hardware::HardwareChoice::None,
        )
        .unwrap();
        unsigned = crate::did::lifecycle::with_extra_key(
            &unsigned,
            &did,
            &root_signer.verifying_key(),
            extra,
        )
        .unwrap();
    }
    let original =
        crate::did::document::sign_document(&unsigned, &root_signer, &root_envelope.id.kid)
            .unwrap();
    crate::keystore::store::write_did_document(&layout, &did, &original).unwrap();
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let keys = f.db.catalog().unwrap().keys;
    let root = keys.iter().find(|k| k.kid == root_envelope.id.kid).unwrap();
    let old = keys.iter().find(|k| k.kid.ends_with("#hot-old")).unwrap();
    let next = keys.iter().find(|k| k.kid.ends_with("#hot-next")).unwrap();
    for (key, role) in [
        (root, KeyRole::Root),
        (old, KeyRole::Hot),
        (next, KeyRole::Hot),
    ] {
        apply_change(
            &mut f,
            CatalogChange::ConfirmRole {
                key_id: key.key_id.clone(),
                role,
            },
        );
    }
    let policy = uuid();
    apply_change(
        &mut f,
        CatalogChange::PublishPolicy {
            policy_id: policy.clone(),
            version: 1,
            content: policy_value(),
        },
    );
    let grant = new_grant(&mut f, &old.key_id, &policy);
    let change = Change::RotateHotKey {
        root_key_id: root.key_id.clone(),
        old_key_id: old.key_id.clone(),
        next_key_id: next.key_id.clone(),
    };
    let p = f.db.prepare(1002, change, now()).unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    // Inject a crash after approval commits, before the filesystem projection.
    let result =
        f.db.commit_secret(1002, &p.operation_id, &p.digest, now(), Some("test-pass"))
            .unwrap()
            .unwrap();
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        original
    );
    assert!(f
        .db
        .authorize_http(&grant.principal_id, &grant.grant_id, &canonical(), now())
        .is_err());
    f.db.recovery(&f.config, now()).unwrap();
    let installed = crate::keystore::store::read_did_document(&layout, &did).unwrap();
    assert_eq!(installed, result["document"]);
    assert!(anp::authentication::find_verification_method(&installed, &old.kid).is_none());
    assert!(anp::authentication::find_verification_method(&installed, &next.kid).is_some());
    assert_eq!(
        f.db.catalog()
            .unwrap()
            .keys
            .iter()
            .find(|k| k.key_id == old.key_id)
            .unwrap()
            .state,
        "retired"
    );
    assert!(f
        .db
        .complete_secret_operation(1002, &p.operation_id, &p.digest, now(), "test-pass")
        .is_err());
    let fresh = new_grant(&mut f, &next.key_id, &policy);
    assert!(f
        .db
        .authorize_http(&fresh.principal_id, &fresh.grant_id, &canonical(), now())
        .is_ok());
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        installed
    );
    verify_audit(&f.db.connection).unwrap();
}

#[test]
fn durable_http_result_preserves_covered_type_but_not_private_application_headers() {
    let (mut f, key, policy) = grant_fixture();
    let grant = new_grant(&mut f, &key, &policy);
    let request =
        crate::security::http::CanonicalHttpRequest::new(crate::security::http::HttpRequest {
            method: "GET".into(),
            url: "https://service.example.com/v1/orders".into(),
            headers: std::collections::BTreeMap::from([
                ("Content-Type".into(), "application/json".into()),
                (
                    "X-Api-Key".into(),
                    "must-not-persist-test-credential".into(),
                ),
            ]),
            body: crate::security::http::Body::Absent {},
            nonce: None,
        })
        .unwrap();
    let id = uuid();
    let result = crate::security::executor::execute(
        &mut f.db,
        &grant.principal_id,
        &grant.grant_id,
        &id,
        &request,
        &FixedClock,
        |_, _, _| Ok(fake_signed()),
    )
    .unwrap();
    let value = serde_json::to_value(&result).unwrap();
    assert_eq!(
        value["result"]["headers"]["content-type"],
        "application/json"
    );
    assert!(!serde_json::to_string(&value)
        .unwrap()
        .contains("must-not-persist"));
    let stored: Vec<u8> =
        f.db.connection
            .query_row(
                "SELECT result FROM requests WHERE request_id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
    assert!(!String::from_utf8(stored)
        .unwrap()
        .contains("must-not-persist"));
}

#[test]
fn independent_checkpoint_detects_consistent_rollback_and_fork() {
    let mut f = Fixture::new();
    let path = f.dir.join("state.sqlite");
    let id = &f.config.instance_id.clone();
    let initial = checkpoint::inspect(&path, id, None).unwrap();
    let backup = f.dir.join("before.sqlite");
    std::fs::copy(&path, &backup).unwrap();
    let op = f.disable();
    let tip = checkpoint::inspect(&path, id, Some(&initial)).unwrap();
    assert!(tip.sequence > initial.sequence);
    assert_eq!(checkpoint::inspect(&path, id, Some(&tip)).unwrap(), tip);
    // Both histories have valid local chains; the independently saved tip
    // distinguishes the older snapshot, including after copying all local files.
    assert!(checkpoint::inspect(&backup, id, Some(&tip)).is_err());
    let fork = open(&backup).unwrap();
    let tx = fork.unchecked_transaction().unwrap();
    append(&tx, &json!({"event":"alternate_branch"})).unwrap();
    tx.commit().unwrap();
    drop(fork);
    assert!(checkpoint::inspect(&backup, id, Some(&tip)).is_err());
    // A retained prefix says nothing about an unobserved suffix.
    assert!(checkpoint::inspect(&backup, id, Some(&initial)).is_ok());
    assert!(checkpoint::inspect(&path, &uuid(), Some(&tip)).is_err());
    assert!(checkpoint::inspect(&path, id, None).is_ok());
    f.db.commit(1002, &op.operation_id, &op.digest, now())
        .unwrap();
    assert!(checkpoint::inspect(&path, id, Some(&tip)).unwrap().sequence > tip.sequence);
}

#[test]
fn checkpoint_rejects_corruption_bad_formats_and_unsafe_inputs_without_writes() {
    let f = Fixture::new();
    let path = f.dir.join("state.sqlite");
    let id = &f.config.instance_id;
    let before = std::fs::read(&path).unwrap();
    let tip = checkpoint::inspect(&path, id, None).unwrap();
    assert_eq!(before, std::fs::read(&path).unwrap());
    let retained = f.dir.join("retained.json");
    std::fs::write(&retained, serde_json::to_vec(&tip).unwrap()).unwrap();
    assert_eq!(checkpoint::read(&retained).unwrap(), tip);
    for bytes in [
        b"{}".to_vec(),
        vec![b' '; 4097],
        b"{\"version\":2}".to_vec(),
    ] {
        std::fs::write(&retained, bytes).unwrap();
        assert!(checkpoint::read(&retained).is_err());
    }
    let link = f.dir.join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(checkpoint::inspect(&link, id, None).is_err());
    assert!(checkpoint::read(&link).is_err());
    for mutate in [
        "UPDATE audit_events SET event_digest='bad' WHERE seq=1",
        "PRAGMA user_version=999",
    ] {
        let copy = f.dir.join(format!("{}.sqlite", uuid()));
        std::fs::copy(&path, &copy).unwrap();
        let db = open(&copy).unwrap();
        db.execute_batch(mutate).unwrap();
        drop(db);
        assert!(checkpoint::inspect(&copy, id, Some(&tip)).is_err());
    }
    let mut bad = tip.clone();
    bad.sequence = 0;
    assert!(checkpoint::inspect(&path, id, Some(&bad)).is_err());
    bad = tip.clone();
    bad.digest = "G".repeat(64);
    assert!(checkpoint::inspect(&path, id, Some(&bad)).is_err());
    bad = tip;
    bad.version = 2;
    assert!(checkpoint::inspect(&path, id, Some(&bad)).is_err());
    assert!(!f.dir.join("missing.sqlite").exists());
    assert!(checkpoint::inspect(&f.dir.join("missing.sqlite"), id, None).is_err());
    assert!(!f.dir.join("missing.sqlite").exists());
}

#[test]
fn fixed_audit_source_binds_previous_and_refuses_implicit_enrollment() {
    let mut f = Fixture::new();
    let path = f.dir.join("state.sqlite");
    let id = f.config.instance_id.clone();
    let first = checkpoint::source(&path, &id,
        br#"{"version":1,"enroll":true,"previous":null}"#.as_slice()).unwrap();
    let op = f.disable();
    let request = serde_json::to_vec(&checkpoint::SourceRequest {
        version: 1, enroll: false, previous: Some(first.checkpoint.clone()),
    }).unwrap();
    let second = checkpoint::source(&path, &id, request.as_slice()).unwrap();
    assert_eq!(second.previous, Some(first.checkpoint));
    assert!(second.checkpoint.sequence > second.previous.unwrap().sequence);
    for bad in [
        br#"{"version":1,"enroll":false,"previous":null}"#.to_vec(),
        br#"{"version":2,"enroll":true,"previous":null}"#.to_vec(),
        br#"{"version":1,"enroll":true,"previous":null,"database":"/other"}"#.to_vec(),
        vec![b' ';4097],
    ] {
        assert!(checkpoint::source(&path, &id, bad.as_slice()).is_err());
    }
    // Collection neither consumes an operation nor changes authorization state.
    f.db.commit(1002, &op.operation_id, &op.digest, now()).unwrap();
}
