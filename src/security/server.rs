//! Linux v2 transaction signer; production release acceptance remains separate.
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener as StdListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UnixListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

use super::protocol::{AdminRequest, DataRequest, Envelope, Reply, VERSION};
use super::{config::ServiceConfig, paths, protocol, DeadlineStream};
use crate::daemon::autolock::Autolock;
use crate::daemon::peer::{peer_identity, self_uid, PeerPolicy};
use crate::daemon::state::{DaemonState, Roots, SigningGates};
use crate::error::{KeydError, Result};
use crate::keystore::layout::KeydLayout;
use crate::persistence::clock::{Clock, SystemClock};
use crate::persistence::{Change, Database};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};

pub struct Boundary {
    config: ServiceConfig,
    vaults: BTreeMap<String, DaemonState>,
    // State changes serialize; KDF has a separate, non-queueing single slot.
    // Vault generation checks cancel unlocks that overlap LOCK_ALL.
    admin_gate: super::coordinator::Coordinator,
    kdf_gate: Mutex<()>,
    database: Mutex<Database>,
    stopped: AtomicBool,
    rates: Mutex<super::limits::RateLimit>,
    projection_healthy: AtomicBool,
    connections: super::limits::Connections,
    se_session: Mutex<Option<super::se_session::Lease>>,
}

#[cfg(all(test, target_os = "macos", feature = "hardware-se"))]
pub(crate) fn exercise_local_se_bridge(
    config: ServiceConfig,
    database: Database,
    grant: crate::persistence::grants::Grant,
    ending: &str,
) -> Database {
    use crate::crypto::hygiene::LockedBytes;
    use std::io::Write;
    let catalog = database.catalog().unwrap();
    let key = catalog
        .keys
        .iter()
        .find(|key| key.key_id == grant.key_id)
        .unwrap();
    let boundary = Arc::new(Boundary::new(config.clone(), database).unwrap());
    let (server, mut helper) = UnixStream::pair().unwrap();
    helper
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    helper
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let worker = boundary.clone();
    let thread = std::thread::spawn(move || worker.connection(server, true));
    protocol::write(
        &mut helper,
        &Envelope {
            version: VERSION,
            request: AdminRequest::StartSeSession {
                vault_id: key.vault_id.clone(),
                did: key.did.clone(),
                kid: key.kid.clone(),
            },
        },
    )
    .unwrap();
    let challenge: Reply = protocol::read(&mut helper).unwrap();
    assert_eq!(challenge.code, "OK");
    assert_eq!(
        challenge.instance_id.as_deref(),
        Some(config.instance_id.as_str())
    );
    let session_id = challenge.data.as_ref().unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let wrapped: crate::keystore::record::WrappedKey =
        serde_json::from_value(challenge.data.unwrap()["envelope"].clone()).unwrap();
    assert_eq!(wrapped.id.kid, key.kid);
    // Fixture-only HS stands in for the signed helper's SE call. The actual
    // management stream, kernel audit session, console observer, KDF, signing,
    // transactions, and disconnect cleanup are exercised without OS mocks.
    protocol::write_hs(
        &mut helper,
        &LockedBytes::fill(|bytes| *bytes = [if ending == "bad-hs" { 30 } else { 29 }; 32])
            .unwrap(),
    )
    .unwrap();
    protocol::write_secret(
        &mut helper,
        if ending == "bad-pass" {
            "wrong-pass"
        } else {
            "test-pass"
        },
    )
    .unwrap();
    let ready: Reply = protocol::read(&mut helper).unwrap();
    if ending == "bad-pass" || ending == "bad-hs" {
        assert_eq!(ready.code, "SE_SESSION_REFUSED");
        drop(helper);
        thread.join().unwrap().unwrap();
        assert!(boundary.se_session.lock().unwrap().is_none());
        assert!(!boundary.stopped.load(Ordering::SeqCst));
        assert_eq!(
            boundary.vaults[&key.vault_id]
                .lock(config.service_uid, None, None)
                .unwrap(),
            0
        );
        return Arc::try_unwrap(boundary)
            .ok()
            .unwrap()
            .database
            .into_inner()
            .unwrap();
    }
    assert_eq!(ready.code, "OK");
    assert_eq!(
        ready.instance_id.as_deref(),
        Some(config.instance_id.as_str())
    );
    protocol::write(
        &mut helper,
        &protocol::SeHeartbeat {
            session_id,
            sequence: 1,
        },
    )
    .unwrap();
    let beat: Reply = protocol::read(&mut helper).unwrap();
    assert_eq!(beat.code, "OK");
    assert_eq!(
        beat.instance_id.as_deref(),
        Some(config.instance_id.as_str())
    );
    let request_id = "12345678-1234-4234-8234-123456789012".to_string();
    let http = super::http::HttpRequest {
        method: "GET".into(),
        url: "https://service.example.com/v1/orders".into(),
        headers: Default::default(),
        body: super::http::Body::Absent {},
        nonce: None,
    };
    let signed = boundary.data(
        1005,
        &grant.principal_id,
        DataRequest::SignHttp {
            grant_id: grant.grant_id.clone(),
            request_id: request_id.clone(),
            http,
        },
    );
    assert_eq!(signed.code, "OK");
    let signed = signed.data.unwrap();
    let headers: BTreeMap<String, String> =
        serde_json::from_value(signed["result"]["headers"].clone()).unwrap();
    assert!(headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("signature")));
    let (document, _) = boundary.vaults[&key.vault_id]
        .get_document(config.service_uid, &key.did)
        .unwrap();
    let document = serde_json::from_slice(&document).unwrap();
    anp::authentication::verify_http_message_signature(
        &document,
        "GET",
        "https://service.example.com/v1/orders",
        &headers,
        None,
    )
    .unwrap();
    assert!(anp::authentication::verify_http_message_signature(
        &document,
        "GET",
        "https://service.example.com/other",
        &headers,
        None
    )
    .is_err());
    // Disconnect must lock the real loaded key, revoke the grant, and hide the
    // previously committed result before the next successful data response.
    if ending == "replay" {
        let challenge = protocol::SeHeartbeat {
            session_id: "wrong-session".into(),
            sequence: 1,
        };
        protocol::write(&mut helper, &challenge).unwrap();
        assert!(protocol::read::<_, Reply>(&mut helper).is_err());
    } else if ending == "silence" {
        // Deliberately withhold heartbeats. Server-side whole-frame expiry must
        // revoke authority even while the helper process/socket remain alive.
        assert!(protocol::read::<_, Reply>(&mut helper).is_err());
    } else {
        assert_eq!(ending, "disconnect");
    }
    helper.flush().unwrap();
    drop(helper);
    thread.join().unwrap().unwrap();
    assert!(boundary.se_session.lock().unwrap().is_none());
    assert!(!boundary.stopped.load(Ordering::SeqCst));
    assert_eq!(
        boundary
            .database
            .lock()
            .unwrap()
            .grant_status(
                &grant.principal_id,
                &grant.grant_id,
                SystemClock.now().unwrap()
            )
            .unwrap()
            .state,
        "revoked"
    );
    let status = boundary.data(
        1005,
        &grant.principal_id,
        DataRequest::RequestStatus { request_id },
    );
    assert_eq!(status.code, "OK");
    assert!(status.data.unwrap().get("result").is_none());
    let state = &boundary.vaults[&key.vault_id];
    assert_eq!(
        state.lock(config.service_uid, None, None).unwrap(),
        0,
        "disconnect already removed the loaded key"
    );
    let boundary = Arc::try_unwrap(boundary).ok().unwrap();
    boundary.database.into_inner().unwrap()
}

impl Boundary {
    pub fn new(config: ServiceConfig, database: Database) -> Result<Self> {
        config.validate()?;
        let vaults = config
            .vault_ids
            .iter()
            .map(|id| {
                let state = DaemonState::new(
                    Roots::Single(KeydLayout::at(
                        config.vault(id).expect("validated vault ID"),
                    )),
                    PeerPolicy::default(),
                    Autolock::idle(Duration::from_secs(900)),
                    SigningGates::new(false, false),
                );
                (id.clone(), state)
            })
            .collect();
        let admin_gate = super::coordinator::Coordinator::new(&config.limits);
        Ok(Self {
            config,
            vaults,
            admin_gate,
            kdf_gate: Mutex::new(()),
            database: Mutex::new(database),
            stopped: AtomicBool::new(false),
            rates: Mutex::new(Default::default()),
            projection_healthy: AtomicBool::new(false),
            connections: Default::default(),
            se_session: Mutex::new(None),
        })
    }

    fn capabilities(&self, principal_id: Option<String>) -> Reply {
        let mut reply = Reply::code("OK");
        reply.signing_available = !self.stopped.load(Ordering::SeqCst);
        reply.protected_supported = self.config.protected_supported();
        reply.instance_id = Some(self.config.instance_id.clone());
        reply.principal_id = principal_id;
        reply.data = Some(
            json!({"audit_projection_healthy":self.projection_healthy.load(Ordering::SeqCst),"transaction_executor_available":true,
                "se_login_sessions":cfg!(all(target_os="macos",feature="hardware-se")) && self.config.mode == "macos-boundary-preview" && self.config.limits.admin_connections >= 2}),
        );
        match self.database.lock() {
            Ok(db) => reply.boot_epoch = Some(db.boot_epoch),
            Err(_) => {
                self.emergency();
                return Reply::code("AUDIT_UNAVAILABLE");
            }
        }
        reply
    }

    fn lock_all(&self) {
        for state in self.vaults.values() {
            state.lock_everything();
        }
    }

    // Caller holds the coordinator and DB lock, including before result delivery.
    fn check_se_session(&self, db: &mut Database) -> Result<()> {
        let mut session = self.se_session.lock().map_err(|_| KeydError::Locked)?;
        if session.as_ref().is_some_and(|lease| !lease.live()) {
            let lease = session.take().expect("present lease");
            self.lock_all();
            if let Err(error) = db.end_se_session(lease.actor, &lease.id) {
                self.emergency();
                return Err(error);
            }
            return Err(KeydError::Misuse("SE_SESSION_ENDED".into()));
        }
        Ok(())
    }

    fn finish_se_session(&self, id: &str) -> Result<()> {
        let _guard = self.admin_gate.enter(true)?;
        let mut session = self.se_session.lock().map_err(|_| KeydError::Locked)?;
        if session.as_ref().is_some_and(|lease| lease.id == id) {
            let lease = session.take().expect("present lease");
            self.lock_all();
            self.database
                .lock()
                .map_err(|_| KeydError::Locked)?
                .end_se_session(lease.actor, id)?;
        }
        Ok(())
    }

    fn se_connection(
        &self,
        actor: u32,
        io: &mut DeadlineStream,
        vault: &str,
        did: &str,
        kid: &str,
    ) -> Result<()> {
        use super::se_session;
        use crate::keystore::record::HardwareRoot;
        if self.config.limits.admin_connections < 2 {
            return protocol::write(io, &Reply::code("RESOURCE_BUSY"));
        }
        let socket = io.clone_socket()?;
        let audit_session = match se_session::peer_session(&socket, actor) {
            Ok(session) if self.config.mode == "macos-boundary-preview" => session,
            _ => return protocol::write(io, &Reply::code("SE_LOGIN_SESSION_REQUIRED")),
        };
        let console_epoch = se_session::console_epoch();
        let _kdf = match self.kdf_gate.try_lock() {
            Ok(guard) => guard,
            Err(_) => return protocol::write(io, &Reply::code("RESOURCE_BUSY")),
        };
        let mut random = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut random);
        let id: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let setup = (|| -> Result<()> {
            let state = self.vaults.get(vault).ok_or(KeydError::Locked)?;
            let fragment = kid
                .strip_prefix(&format!("{did}#"))
                .filter(|s| !s.is_empty() && !s.contains('#'))
                .ok_or(KeydError::Locked)?;
            let (wrapped, epoch, generation) = {
                let _guard = self.admin_gate.enter(true)?;
                if self.stopped.load(Ordering::SeqCst) {
                    return Err(KeydError::Locked);
                }
                if self
                    .se_session
                    .lock()
                    .map_err(|_| KeydError::Locked)?
                    .is_some()
                {
                    return Err(KeydError::Locked);
                }
                let db = self.database.lock().map_err(|_| KeydError::Locked)?;
                db.check_key(vault, did, kid)?;
                if !db.catalog()?.keys.iter().any(|key| {
                    key.vault_id == vault
                        && key.did == did
                        && key.kid == kid
                        && key.role == crate::persistence::catalog::KeyRole::Hot
                        && key.state == "active"
                }) {
                    return Err(KeydError::Locked);
                }
                let (generation, wrapped) =
                    state.se_envelope(self.config.service_uid, did, fragment)?;
                wrapped.validate()?;
                wrapped.verify_aad()?;
                if !matches!(wrapped.hardware, Some(HardwareRoot::SecureEnclave { .. })) {
                    return Err(KeydError::Locked);
                }
                (wrapped, db.mutation_epoch()?, generation)
            };
            let mut challenge = Reply::code("OK");
            challenge.instance_id = Some(self.config.instance_id.clone());
            challenge.data = Some(
                json!({"session_id":id,"envelope":wrapped,"max_seconds":se_session::MAX_SECONDS}),
            );
            io.reset(Duration::from_secs(30));
            protocol::write(io, &challenge)?;
            let hs = protocol::read_hs(io)?;
            let passphrase = protocol::read_secret(io)?;
            state.unlock_se_guarded(self.config.service_uid, &wrapped, passphrase, &hs, generation, || {
                let guard = self.admin_gate.enter(true)?;
                if self.stopped.load(Ordering::SeqCst) || !se_session::login_active(actor, audit_session)
                    || se_session::console_epoch() != console_epoch {
                    return Err(KeydError::Locked);
                }
                let mut db = self.database.lock().map_err(|_| KeydError::Locked)?;
                if db.mutation_epoch()? != epoch { return Err(KeydError::Locked); }
                db.check_key(vault, did, kid)?;
                let mut current = self.se_session.lock().map_err(|_| KeydError::Locked)?;
                if current.is_some() { return Err(KeydError::Locked); }
                let mut lease = se_session::Lease::new(id.clone(), actor, audit_session, socket, se_session::now()?)?;
                lease.console_epoch = console_epoch;
                if let Err(error) = db.record(json!({"event":"SE_SESSION_STARTED","actor":actor,"session_id":id,"vault_id":vault,"kid":kid})) {
                    self.emergency();
                    return Err(error);
                }
                *current = Some(lease);
                Ok(guard)
            })?;
            io.reset(Duration::from_secs(5));
            protocol::write(io, &self.capabilities(None))?;
            Ok(())
        })();
        drop(_kdf);
        if setup.is_err() {
            if self.finish_se_session(&id).is_err() {
                self.emergency();
            }
            let audited = self.record(json!({"event":"SE_SESSION_REFUSED","actor":actor,
                "session_id":id,"vault_id":vault,"kid":kid}));
            io.reset(Duration::from_secs(5));
            return protocol::write(
                io,
                &Reply::code(if !audited || self.stopped.load(Ordering::SeqCst) {
                    "AUDIT_UNAVAILABLE"
                } else {
                    "SE_SESSION_REFUSED"
                }),
            );
        }
        loop {
            io.reset(Duration::from_secs(se_session::HEARTBEAT_SECONDS));
            let heartbeat: super::protocol::SeHeartbeat = match protocol::read(io) {
                Ok(value) => value,
                Err(_) => break,
            };
            let outcome = (|| -> Result<()> {
                let _guard = self.admin_gate.enter(true)?;
                if self.stopped.load(Ordering::SeqCst) {
                    return Err(KeydError::Locked);
                }
                let mut session = self.se_session.lock().map_err(|_| KeydError::Locked)?;
                let lease = session
                    .as_mut()
                    .filter(|lease| lease.id == id)
                    .ok_or(KeydError::Locked)?;
                if !lease.live() {
                    return Err(KeydError::Locked);
                }
                lease.heartbeat(
                    &heartbeat.session_id,
                    heartbeat.sequence,
                    se_session::now()?,
                )?;
                Ok(())
            })();
            if outcome.is_err() || protocol::write(io, &self.capabilities(None)).is_err() {
                break;
            }
        }
        if self.finish_se_session(&id).is_err() {
            self.emergency();
        }
        Ok(())
    }

    fn connection(&self, stream: UnixStream, admin: bool) -> Result<()> {
        let peer = peer_identity(&stream)?;
        let mut io = DeadlineStream::new(
            stream,
            Duration::from_secs(self.config.limits.frame_seconds),
        );
        // Authorize before reading any payload, even on the management listener.
        let principal = if admin {
            if !self.config.admin_uids.contains(&peer.uid) {
                protocol::write(&mut io, &Reply::code("ADMIN_REQUIRED"))?;
                return Ok(());
            }
            None
        } else {
            if self.stopped.load(Ordering::SeqCst) {
                protocol::write(&mut io, &Reply::code("AUDIT_UNAVAILABLE"))?;
                return Ok(());
            }
            let principal = match self.database.lock() {
                Ok(db) => db.principal(peer.uid),
                Err(_) => Err(KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into())),
            };
            match principal {
                Ok(Some(principal)) => Some(principal.principal_id),
                Ok(None) => {
                    protocol::write(&mut io, &Reply::code("PRINCIPAL_DISABLED"))?;
                    return Ok(());
                }
                Err(_) => {
                    self.emergency();
                    protocol::write(&mut io, &Reply::code("AUDIT_UNAVAILABLE"))?;
                    return Ok(());
                }
            }
        };
        let _principal_slot = if !admin {
            match self
                .connections
                .enter(peer.uid, self.config.limits.principal_connections)
            {
                Ok(permit) => Some(permit),
                Err(_) => {
                    protocol::write(&mut io, &Reply::code("RESOURCE_BUSY"))?;
                    return Ok(());
                }
            }
        } else {
            None
        };
        // Keep coordinated data execution through the bounded wire delivery:
        // session teardown/revocation cannot acknowledge while a previously
        // authorized signature frame is still waiting to be sent.
        let mut delivery_guard = None;
        let mut reply = if admin {
            match protocol::read::<_, Envelope<AdminRequest>>(&mut io) {
                Ok(request) if request.version != VERSION => {
                    Reply::code("PROTOCOL_VERSION_UNSUPPORTED")
                }
                Ok(request) => {
                    if let AdminRequest::StartSeSession { vault_id, did, kid } = request.request {
                        return self.se_connection(peer.uid, &mut io, &vault_id, &did, &kid);
                    }
                    let secret = if matches!(
                        request.request,
                        AdminRequest::Unlock { .. } | AdminRequest::CompleteSecretOperation { .. }
                    ) {
                        match protocol::read_secret(&mut io) {
                            Ok(secret) => Some(secret),
                            Err(_) => {
                                return protocol::write(&mut io, &Reply::code("PROTOCOL_INVALID"))
                            }
                        }
                    } else {
                        None
                    };
                    self.admin(peer.uid, request.request, secret)
                }
                Err(_) => Reply::code("PROTOCOL_INVALID"),
            }
        } else {
            match protocol::read::<_, Envelope<DataRequest>>(&mut io) {
                Ok(request) if request.version != VERSION => {
                    Reply::code("PROTOCOL_VERSION_UNSUPPORTED")
                }
                Ok(request) => match self.admin_gate.enter(false) {
                    Ok(guard) => {
                        delivery_guard = Some(guard);
                        self.data_locked(
                            peer.uid,
                            principal.as_deref().expect("authenticated principal"),
                            request.request,
                        )
                    }
                    Err(_) => Reply::code("RESOURCE_BUSY"),
                },
                Err(_) => Reply::code("PROTOCOL_INVALID"),
            }
        };
        if delivery_guard.is_some() {
            let check = self
                .database
                .lock()
                .map_err(|_| KeydError::Locked)
                .and_then(|mut db| self.check_se_session(&mut db));
            if let Err(error) = check {
                reply = if matches!(error, KeydError::Misuse(_)) {
                    Reply::code("SE_SESSION_ENDED")
                } else {
                    self.emergency();
                    Reply::code("AUDIT_UNAVAILABLE")
                };
            }
        }
        if reply.code == "OK" {
            reply.signing_available = !self.stopped.load(Ordering::SeqCst);
            reply.protected_supported = self.config.protected_supported();
            reply.instance_id = Some(self.config.instance_id.clone());
        }
        // New deadline for delivery; no secret payload is reflected in errors.
        io.reset(Duration::from_secs(self.config.limits.response_seconds));
        protocol::write(&mut io, &reply)
        // Ordinary connections are one-shot. START_SE_SESSION is the explicit,
        // authenticated heartbeat exception with a non-renewable 900s deadline.
    }

    #[cfg(all(test, target_os = "macos", feature = "hardware-se"))]
    fn data(&self, uid: u32, principal: &str, request: DataRequest) -> Reply {
        let Ok(_guard) = self.admin_gate.enter(false) else {
            return Reply::code("RESOURCE_BUSY");
        };
        self.data_locked(uid, principal, request)
    }

    fn data_locked(&self, uid: u32, principal: &str, request: DataRequest) -> Reply {
        // Recheck the live principal after reading the frame. A stalled connection
        // must not retain access after DisablePrincipal commits.
        let rate_now = match SystemClock.now() {
            Ok(t) => t.monotonic_ms,
            Err(_) => return Reply::code("AUDIT_UNAVAILABLE"),
        };
        if !self
            .rates
            .lock()
            .map(|mut r| r.accept(principal, rate_now, &self.config.limits))
            .unwrap_or(false)
        {
            return Reply::code("RESOURCE_BUSY");
        }
        let result = (|| -> Result<Reply> {
            if self.stopped.load(Ordering::SeqCst) {
                return Err(KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()));
            }
            let mut db = self
                .database
                .lock()
                .map_err(|_| KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()))?;
            self.check_se_session(&mut db)?;
            if db.principal(uid)?.as_ref().map(|p| p.principal_id.as_str()) != Some(principal) {
                return Err(KeydError::Misuse("PRINCIPAL_DISABLED".into()));
            }
            let now = SystemClock.now()?;
            let mut reply = Reply::code("OK");
            reply.principal_id = Some(principal.into());
            match request {
                DataRequest::Capabilities {} => {
                    reply.boot_epoch = Some(db.boot_epoch);
                    let mut operations = vec![
                        "GET_CAPABILITIES",
                        "LIST_AUTHORIZED_KEYS",
                        "GET_GRANT_STATUS",
                        "GET_DOCUMENT",
                        "SIGN_HTTP",
                        "RENEW_GRANT",
                        "GET_REQUEST_STATUS",
                    ];
                    let mut purposes = vec!["http-authentication"];
                    if self.config.features.sign_origin_proof {
                        operations.push("SIGN_ORIGIN_PROOF");
                        purposes.push("origin-proof");
                    }
                    let signing_purposes = self.config.features.sign_purpose.enabled_names();
                    if !signing_purposes.is_empty() {
                        operations.push("SIGN_PURPOSE");
                        purposes.push("purpose-signing");
                    }
                    reply.data = Some(
                        json!({"protocol_version":2,"profile":"anp-http-v2","max_body_bytes":16384,"transaction_executor_available":true,"audit_projection_healthy":self.projection_healthy.load(Ordering::SeqCst),"capability_schema":1,"operations":operations,"purposes":purposes,"signing_purposes":signing_purposes,"grant_kinds":["request","session"]}),
                    );
                }
                DataRequest::ListAuthorizedKeys {} => {
                    let keys = db.authorized_keys(principal, now)?;
                    reply.data = Some(
                        json!({"keys":keys.iter().map(|k|json!({"key_id":k.key_id,"did":k.did,"kid":k.kid})).collect::<Vec<_>>()}),
                    );
                }
                DataRequest::GrantStatus { grant_id } => {
                    reply.data = Some(serde_json::to_value(
                        db.grant_status(principal, &grant_id, now)?,
                    )?);
                }
                DataRequest::Document { key_id } => {
                    let key = db
                        .authorized_keys(principal, now)?
                        .into_iter()
                        .find(|k| k.key_id == key_id)
                        .ok_or_else(|| KeydError::Misuse("GRANT_INVALID".into()))?;
                    let state = self
                        .vaults
                        .get(&key.vault_id)
                        .ok_or_else(|| KeydError::Misuse("GRANT_INVALID".into()))?;
                    let (bytes, _) = state.get_document(self.config.service_uid, &key.did)?;
                    reply.data = Some(
                        json!({"key_id":key_id,"document":serde_json::from_slice::<serde_json::Value>(&bytes)?}),
                    );
                }
                DataRequest::SignHttp {
                    grant_id,
                    request_id,
                    http,
                } => {
                    if !crate::principal::validate_uuid(&request_id) {
                        return Err(KeydError::Misuse("REQUEST_ID_INVALID".into()));
                    }
                    let canonical = super::http::CanonicalHttpRequest::new(http)?;
                    let status = super::executor::execute(
                        &mut db,
                        principal,
                        &grant_id,
                        &request_id,
                        &canonical,
                        &SystemClock,
                        |key, expiry, deadline| {
                            if self
                                .se_session
                                .lock()
                                .map_err(|_| KeydError::Locked)?
                                .as_ref()
                                .is_some_and(|lease| !lease.live())
                            {
                                return Err(KeydError::Locked);
                            }
                            let state = self.vaults.get(&key.vault_id).ok_or_else(|| {
                                KeydError::Protocol("missing managed vault".into())
                            })?;
                            state.sign_protected(
                                self.config.service_uid,
                                key,
                                &canonical,
                                expiry,
                                deadline,
                            )
                        },
                    )?;
                    reply.data = Some(serde_json::to_value(status)?);
                }
                DataRequest::SignOriginProof { .. } if !self.config.features.sign_origin_proof => {
                    return Err(KeydError::Misuse("OPERATION_DISABLED".into()));
                }
                DataRequest::SignOriginProof {
                    grant_id,
                    request_id,
                    origin,
                } => {
                    if !crate::principal::validate_uuid(&request_id) {
                        return Err(KeydError::Misuse("REQUEST_ID_INVALID".into()));
                    }
                    let proof = origin.validate(now.wall)?;
                    let status = super::executor::execute_origin(
                        &mut db,
                        principal,
                        &grant_id,
                        &request_id,
                        &proof,
                        &SystemClock,
                        |key, proof, created| {
                            if self
                                .se_session
                                .lock()
                                .map_err(|_| KeydError::Locked)?
                                .as_ref()
                                .is_some_and(|lease| !lease.live())
                            {
                                return Err(KeydError::Locked);
                            }
                            let state = self.vaults.get(&key.vault_id).ok_or_else(|| {
                                KeydError::Protocol("missing managed vault".into())
                            })?;
                            state.sign_origin_proof(self.config.service_uid, key, proof, created)
                        },
                    )?;
                    reply.data = Some(serde_json::to_value(status)?);
                }
                DataRequest::SignPurpose {
                    grant_id,
                    request_id,
                    purpose,
                    domain,
                    payload,
                } => {
                    // 未知标签永远是 PURPOSE_INVALID,和开关状态无关;已知但没开
                    // 的那一路是 OPERATION_DISABLED,调用方据此决定要不要降级。
                    let purpose = super::purpose::SigningPurpose::parse(&purpose)?;
                    if !self.config.features.sign_purpose.enabled(purpose) {
                        return Err(KeydError::Misuse("OPERATION_DISABLED".into()));
                    }
                    if !crate::principal::validate_uuid(&request_id) {
                        return Err(KeydError::Misuse("REQUEST_ID_INVALID".into()));
                    }
                    let request = super::purpose::PurposeRequest::from_wire(
                        purpose.name(),
                        domain,
                        &payload,
                    )?;
                    let status = super::executor::execute_purpose(
                        &mut db,
                        principal,
                        &grant_id,
                        &request_id,
                        &request,
                        &SystemClock,
                        |key, request| {
                            if self
                                .se_session
                                .lock()
                                .map_err(|_| KeydError::Locked)?
                                .as_ref()
                                .is_some_and(|lease| !lease.live())
                            {
                                return Err(KeydError::Locked);
                            }
                            let state = self.vaults.get(&key.vault_id).ok_or_else(|| {
                                KeydError::Protocol("missing managed vault".into())
                            })?;
                            state.sign_purpose(self.config.service_uid, key, request)
                        },
                    )?;
                    reply.data = Some(serde_json::to_value(status)?);
                }
                DataRequest::RenewGrant { grant_id, expiry } => {
                    reply.data = Some(serde_json::to_value(
                        db.renew_grant(principal, &grant_id, expiry, now)?,
                    )?);
                }
                DataRequest::RequestStatus { request_id } => {
                    if !crate::principal::validate_uuid(&request_id) {
                        return Err(KeydError::Misuse("REQUEST_ID_INVALID".into()));
                    }
                    reply.data = Some(serde_json::to_value(db.request_status(
                        principal,
                        &request_id,
                        now,
                    )?)?);
                }
            }
            // Recheck before releasing signatures or cached results. Logout,
            // disconnect or a stale heartbeat during signing suppresses delivery.
            self.check_se_session(&mut db)?;
            Ok(reply)
        })();
        match result {
            Ok(reply) => reply,
            Err(KeydError::Misuse(code)) => Reply::code(&code),
            Err(_) => {
                self.emergency();
                Reply::code("AUDIT_UNAVAILABLE")
            }
        }
    }

    fn maintenance(&self) {
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        let Ok(_permit) = self.admin_gate.enter(false) else {
            return;
        };
        let session_check = self
            .database
            .lock()
            .map_err(|_| KeydError::Locked)
            .and_then(|mut db| self.check_se_session(&mut db));
        if let Err(error) = session_check {
            if !matches!(error, KeydError::Misuse(_)) {
                self.emergency();
            }
            if self.stopped.load(Ordering::SeqCst) {
                return;
            }
        }
        let count: usize = self
            .vaults
            .values()
            .map(|v| v.sweep_protected(Instant::now()))
            .sum();
        if count > 0 && !self.record(json!({"event":"AUTOLOCKED","count":count})) {
            return;
        }
        let result = (|| -> Result<()> {
            self.database
                .lock()
                .map_err(|_| KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()))?
                .prune_results(SystemClock.now()?)?;
            Ok(())
        })();
        if result.is_err() {
            self.emergency();
        }
    }

    fn emergency(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.lock_all();
    }
    fn record(&self, event: serde_json::Value) -> bool {
        let result = self
            .database
            .lock()
            .map_err(|_| ())
            .and_then(|mut db| db.record(event).map_err(|_| ()));
        if result.is_err() {
            self.emergency();
            false
        } else {
            true
        }
    }

    fn admin(
        &self,
        actor: u32,
        request: AdminRequest,
        secret: Option<zeroize::Zeroizing<String>>,
    ) -> Reply {
        if self.stopped.load(Ordering::SeqCst) {
            self.lock_all();
            return Reply::code("AUDIT_UNAVAILABLE");
        }
        if matches!(request, AdminRequest::Capabilities {}) {
            return self.capabilities(None);
        }
        // Never queue a second KDF on the remaining admin connection slot.
        // This leaves capacity for a concurrent LOCK_ALL.
        let unlocking = matches!(
            request,
            AdminRequest::Unlock { .. } | AdminRequest::CompleteSecretOperation { .. }
        );
        let _kdf_guard = if unlocking {
            match self.kdf_gate.try_lock() {
                Ok(guard) => Some(guard),
                Err(_) => return Reply::code("RESOURCE_BUSY"),
            }
        } else {
            None
        };
        let _guard = if unlocking {
            None
        } else {
            match self.admin_gate.enter(true) {
                Ok(guard) => Some(guard),
                Err(_) => {
                    return Reply::code("RESOURCE_BUSY");
                }
            }
        };
        if self.stopped.load(Ordering::SeqCst) {
            return Reply::code("AUDIT_UNAVAILABLE");
        }
        if !unlocking {
            let result = self
                .database
                .lock()
                .map_err(|_| KeydError::Locked)
                .and_then(|mut db| self.check_se_session(&mut db));
            if let Err(error) = result {
                if matches!(error, KeydError::Misuse(_)) {
                    return Reply::code("SE_SESSION_ENDED");
                }
                self.emergency();
                return Reply::code("AUDIT_UNAVAILABLE");
            }
        }
        match request {
            AdminRequest::StartSeSession { .. } => Reply::code("SE_LOGIN_SESSION_REQUIRED"),
            AdminRequest::CompleteSecretOperation {
                operation_id,
                digest,
            } => {
                let Some(secret) = secret else {
                    return Reply::code("PROTOCOL_INVALID");
                };
                // The one-shot KDF has no queue. Management serialization keeps
                // the approval, key snapshot and signature in a single order.
                let result = (|| -> Result<serde_json::Value> {
                    let _gate = self.admin_gate.enter(true)?;
                    if self.stopped.load(Ordering::SeqCst) {
                        return Err(KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()));
                    }
                    let mut db = self
                        .database
                        .lock()
                        .map_err(|_| KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()))?;
                    if db.commit_changes_keys(&operation_id)? {
                        self.lock_all();
                    }
                    db.complete_secret_operation(
                        actor,
                        &operation_id,
                        &digest,
                        SystemClock.now()?,
                        &secret,
                    )
                })();
                match result {
                    Ok(data) => {
                        let mut reply = Reply::code("OK");
                        reply.data = Some(data);
                        reply
                    }
                    Err(KeydError::Misuse(_)) | Err(KeydError::BadPassphrase) => {
                        Reply::code("ADMIN_OPERATION_INVALID")
                    }
                    Err(_) => {
                        self.emergency();
                        Reply::code("AUDIT_UNAVAILABLE")
                    }
                }
            }
            AdminRequest::Capabilities {} => unreachable!(),
            AdminRequest::Catalog {} => {
                let result = self
                    .database
                    .lock()
                    .map_err(|_| ())
                    .and_then(|db| db.catalog().map_err(|_| ()));
                match result {
                    Ok(catalog) => {
                        let mut reply = Reply::code("OK");
                        reply.catalog = Some(catalog);
                        reply
                    }
                    Err(_) => {
                        self.emergency();
                        Reply::code("AUDIT_UNAVAILABLE")
                    }
                }
            }
            AdminRequest::ListPrincipals {} => {
                let result = self
                    .database
                    .lock()
                    .map_err(|_| ())
                    .and_then(|db| db.principals().map_err(|_| ()));
                match result {
                    Ok(principals) => {
                        let mut reply = Reply::code("OK");
                        reply.principals = Some(principals);
                        reply
                    }
                    Err(_) => {
                        self.emergency();
                        Reply::code("AUDIT_UNAVAILABLE")
                    }
                }
            }
            AdminRequest::Prepare { change } => {
                if let Change::RegisterPrincipal { uid } = &change {
                    if *uid == self.config.service_uid
                        || self.config.admin_uids.contains(uid)
                        || *uid == 0
                    {
                        return Reply::code("ADMIN_OPERATION_INVALID");
                    }
                }
                let Ok(now) = SystemClock.now() else {
                    self.emergency();
                    return Reply::code("AUDIT_UNAVAILABLE");
                };
                let result = self
                    .database
                    .lock()
                    .map_err(|_| KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()))
                    .and_then(|mut db| db.prepare(actor, change, now));
                match result {
                    Ok(prepared) => {
                        let mut reply = Reply::code("OK");
                        reply.prepared = Some(prepared);
                        reply
                    }
                    Err(KeydError::Misuse(_)) => Reply::code("ADMIN_OPERATION_INVALID"),
                    Err(_) => {
                        self.emergency();
                        Reply::code("AUDIT_UNAVAILABLE")
                    }
                }
            }
            AdminRequest::Commit {
                operation_id,
                digest,
            } => {
                let Ok(now) = SystemClock.now() else {
                    self.emergency();
                    return Reply::code("AUDIT_UNAVAILABLE");
                };
                let result = self
                    .database
                    .lock()
                    .map_err(|_| KeydError::Protocol("PERSISTENCE_UNAVAILABLE".into()))
                    .and_then(|mut db| {
                        if db.commit_changes_keys(&operation_id)? {
                            self.lock_all();
                        }
                        db.commit(actor, &operation_id, &digest, now)
                    });
                match result {
                    Ok(()) => Reply::code("OK"),
                    Err(KeydError::Misuse(_)) => Reply::code("ADMIN_OPERATION_INVALID"),
                    Err(_) => {
                        self.emergency();
                        Reply::code("AUDIT_UNAVAILABLE")
                    }
                }
            }
            AdminRequest::LockAll {} => {
                let mut dropped = 0;
                for state in self.vaults.values() {
                    match state.lock(self.config.service_uid, None, None) {
                        Ok(count) => dropped += count,
                        Err(_) => {
                            self.emergency();
                            return Reply::code("RESOURCE_BUSY");
                        }
                    }
                }
                if !self.record(json!({"event":"LOCKED","actor":actor,"dropped":dropped})) {
                    return Reply::code("AUDIT_UNAVAILABLE");
                }
                Reply::code("OK")
            }
            AdminRequest::Unlock { vault_id, did, kid } => {
                let Some(passphrase) = secret else {
                    return Reply::code("PROTOCOL_INVALID");
                };
                let Some(state) = self.vaults.get(&vault_id) else {
                    return Reply::code("KEY_NOT_FOUND");
                };
                let verified = self.database.lock().map_err(|_| ()).and_then(|db| {
                    db.check_key(&vault_id, &did, &kid).map_err(|_| ())?;
                    db.mutation_epoch().map_err(|_| ())
                });
                let Ok(epoch) = verified else {
                    return Reply::code("KEY_ROLE_FORBIDDEN");
                };
                // No disk path or default binding key may be selected by callers.
                let prefix = format!("{did}#");
                let Some(fragment) = kid
                    .strip_prefix(&prefix)
                    .filter(|value| !value.is_empty() && !value.contains('#'))
                else {
                    return Reply::code("KEY_NOT_FOUND");
                };
                let outcome = state.unlock_guarded(
                    self.config.service_uid,
                    &did,
                    Some(fragment),
                    passphrase,
                    || {
                        let guard = self.admin_gate.enter(true).map_err(|_| KeydError::Locked)?;
                        if self.stopped.load(Ordering::SeqCst) {
                            Err(KeydError::Locked)
                        } else {
                            let db = self.database.lock().map_err(|_| KeydError::Locked)?;
                            if db.mutation_epoch()? != epoch {
                                return Err(KeydError::Locked);
                            }
                            db.check_key(&vault_id, &did, &kid)?;
                            Ok(guard)
                        }
                    },
                );
                if !self.record(json!({"event":if outcome.is_ok() {"UNLOCKED"} else {"UNLOCK_REFUSED"},"actor":actor,"vault_id":vault_id,"kid":kid})) {
                    return Reply::code("AUDIT_UNAVAILABLE");
                }
                match outcome {
                    Ok(()) => Reply::code("OK"),
                    Err(_) => Reply::code("UNLOCK_REFUSED"),
                }
            }
        }
    }
}

/// Only unlink the socket inode created by this process.
struct SocketGuard {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if meta.dev() == self.dev && meta.ino() == self.ino {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

fn bind(path: &Path, uid: u32, gid: u32) -> Result<(StdListener, SocketGuard)> {
    paths::socket_parent(path, uid, gid)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let old = paths::socket(path, uid, gid)?;
            match UnixStream::connect(path) {
                Ok(_) => {
                    return Err(KeydError::Misuse(
                        "protected socket is already listening".into(),
                    ))
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
                Err(e) => return Err(e.into()),
            }
            let current = paths::socket(path, uid, gid)?;
            if old.dev() != current.dev() || old.ino() != current.ino() {
                return Err(KeydError::Permission(
                    "socket inode changed during cleanup".into(),
                ));
            }
            fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = StdListener::bind(path)?;
    let meta = fs::symlink_metadata(path)?;
    let guard = SocketGuard {
        path: path.to_path_buf(),
        dev: meta.dev(),
        ino: meta.ino(),
    };
    nix::unistd::chown(path, None, Some(nix::unistd::Gid::from_raw(gid)))
        .map_err(|e| KeydError::Permission(format!("cannot set protected socket group: {e}")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    paths::socket(path, uid, gid)?;
    listener.set_nonblocking(true)?;
    Ok((listener, guard))
}

async fn listen(
    boundary: Arc<Boundary>,
    listener: StdListener,
    admin: bool,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let listener = UnixListener::from_std(listener)?;
    let slots = Arc::new(Semaphore::new(if admin {
        boundary.config.limits.admin_connections
    } else {
        boundary.config.limits.data_connections
    }));
    let mut tasks = JoinSet::new();
    let outcome = loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() { break Ok(()); }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(KeydError::Io(error)),
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                let stream = match stream.into_std() {
                    Ok(stream) => stream,
                    Err(_) => continue,
                };
                if stream.set_nonblocking(false).is_err() { continue; }
                let boundary = boundary.clone();
                tasks.spawn_blocking(move || {
                    let _permit = permit;
                    if let Err(error) = boundary.connection(stream, admin) {
                        tracing::debug!("protected connection closed: {}", error.wire_message());
                    }
                });
            }
        }
    };
    // Drain on both shutdown and listener failure, before clearing keys.
    while tasks.join_next().await.is_some() {}
    outcome
}

#[cfg(target_os = "linux")]
pub(crate) fn harden_process() -> Result<()> {
    let limit = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Both libc calls receive valid pointers/constants; no borrowed memory escapes.
    let result = unsafe {
        nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &limit) == 0
            && nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
            && nix::libc::prctl(nix::libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    };
    if !result {
        return Err(KeydError::Misuse("cannot disable process dumps".into()));
    }
    Ok(())
}
#[cfg(target_os = "macos")]
pub(crate) fn harden_process() -> Result<()> {
    let limit = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // No process dumps. PT_DENY_ATTACH blocks future debugger attachments;
    // separate UIDs remain the authorization boundary, not this defense alone.
    if unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { nix::libc::ptrace(nix::libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } != 0
    {
        return Err(KeydError::Misuse(
            "cannot disable process debugging/dumps".into(),
        ));
    }
    Ok(())
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn harden_process() -> Result<()> {
    super::require_boundary_platform()
}

pub async fn serve(config: ServiceConfig, mut stop: watch::Receiver<bool>) -> Result<()> {
    super::require_boundary_platform()?;
    config.validate()?;
    if self_uid() != config.service_uid {
        return Err(KeydError::Permission(
            "daemon must run as configured service UID".into(),
        ));
    }
    if std::env::vars_os().any(|(key, _)| {
        key.to_string_lossy().starts_with("LD_") || key.to_string_lossy().starts_with("DYLD_")
    }) {
        return Err(KeydError::Misuse(
            "dynamic loader overrides forbidden".into(),
        ));
    }
    paths::validate_chain(&std::env::current_exe()?, &[0], false)?;
    harden_process()?;
    let _lock = paths::instance_lock(&config.state_dir, config.service_uid)?;
    for id in &config.vault_ids {
        paths::state_directory(&config.vault(id)?, config.service_uid)?;
    }
    let mut database = Database::recover(&config, SystemClock.now()?)?;
    // 开关状态必须在链上留一行:事后能回答"这版服务开过哪些签名路"。
    // 每个 purpose 单独一条,不走 FEATURES 的布尔位。
    database.record(
        json!({"event":"FEATURES","sign_origin_proof":config.features.sign_origin_proof}),
    )?;
    for purpose in config.features.sign_purpose.enabled_names() {
        database.record(json!({"event":"SIGN_PURPOSE_ENABLED","purpose":purpose}))?;
    }
    let (sign, _sign_guard) = bind(&config.sign_socket, config.service_uid, config.agent_gid)?;
    let (admin, _admin_guard) = bind(&config.admin_socket, config.service_uid, config.admin_gid)?;
    let boundary = Arc::new(Boundary::new(config, database)?);
    tracing::info!("UID-separated transaction signer listening");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let sweeper = {
        let boundary = boundary.clone();
        let mut sweep_stop = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    changed = sweep_stop.changed() => { if changed.is_err() || *sweep_stop.borrow() { break; } }
                    _ = timer.tick() => {let worker=boundary.clone();if tokio::task::spawn_blocking(move||worker.maintenance()).await.is_err(){boundary.emergency();}}
                }
            }
        })
    };
    let exporter = {
        let boundary = boundary.clone();
        let mut export_stop = shutdown.subscribe();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    changed = export_stop.changed() => {if changed.is_err() || *export_stop.borrow() {break;}}
                    _ = timer.tick() => {
                        let root=boundary.config.state_dir.clone();
                        let outcome=tokio::task::spawn_blocking(move || crate::persistence::projection::export(&root)).await;
                        boundary.projection_healthy.store(matches!(outcome,Ok(Ok(_))),Ordering::SeqCst);
                    }
                }
            }
        })
    };
    let sign_task = listen(boundary.clone(), sign, false, shutdown_rx.clone());
    let admin_task = listen(boundary.clone(), admin, true, shutdown_rx);
    tokio::pin!(sign_task, admin_task);
    let outcome = tokio::select! {
        result = &mut sign_task => {
            boundary.emergency();
            let _ = shutdown.send(true);
            let other = admin_task.await;
            result.and(other)
        }
        result = &mut admin_task => {
            boundary.emergency();
            let _ = shutdown.send(true);
            let other = sign_task.await;
            result.and(other)
        }
        _ = stop.changed() => {
            boundary.emergency();
            let _ = shutdown.send(true);
            let (sign_result, admin_result) = tokio::join!(sign_task, admin_task);
            sign_result.and(admin_result)
        }
    };
    let _ = sweeper.await;
    let _ = exporter.await;
    boundary.lock_all();
    outcome
}
