//! Authenticate the service's kernel UID before any secret can be written.
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

use super::config::ServiceConfig;
use super::protocol::{self, AdminRequest, DataRequest, Envelope, Reply, VERSION};
use super::{paths, DeadlineStream};
use crate::daemon::peer::{peer_identity, self_uid};
use crate::error::{KeydError, Result};

pub struct Client {
    stream: DeadlineStream,
    config: ServiceConfig,
    admin: bool,
}

impl Client {
    /// Foreground login helper: one exact key, no listener, no reconnection.
    pub fn se_session(mut self, vault_id: String, did: String, kid: String, passphrase: Zeroizing<String>) -> Result<Reply> {
        self.management()?;
        super::se_session::require_local_login()?;
        if !cfg!(all(target_os = "macos", feature = "hardware-se"))
            || self.config.mode != "macos-boundary-preview" {
            return Err(KeydError::Misuse("SE_LOGIN_SESSION_REQUIRED".into()));
        }
        paths::validate_chain(&std::env::current_exe()?, &[0], false)?;
        super::server::harden_process()?;
        self.stream.reset(Duration::from_secs(5));
        protocol::write(&mut self.stream, &Envelope { version: VERSION,
            request: AdminRequest::StartSeSession { vault_id, did: did.clone(), kid: kid.clone() } })?;
        let challenge = self.reply()?;
        if challenge.code != "OK" { return Ok(challenge); }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Challenge { session_id: String, envelope: crate::keystore::record::WrappedKey, max_seconds: i64 }
        let challenge: Challenge = serde_json::from_value(challenge.data.ok_or(KeydError::Locked)?)?;
        if challenge.envelope.id.did != did || challenge.envelope.id.kid != kid
            || challenge.max_seconds != super::se_session::MAX_SECONDS
            || challenge.session_id.len() != 64
            || !matches!(challenge.envelope.hardware, Some(crate::keystore::record::HardwareRoot::SecureEnclave { .. })) {
            return Err(KeydError::Locked);
        }
        challenge.envelope.validate()?;
        challenge.envelope.verify_aad()?;
        let hs = crate::keystore::hardware::open_hs(&challenge.envelope)?;
        self.stream.reset(Duration::from_secs(5));
        protocol::write_hs(&mut self.stream, &hs)?;
        protocol::write_secret(&mut self.stream, &passphrase)?;
        drop(hs);
        drop(passphrase);
        self.stream.reset(Duration::from_secs(30));
        let reply = self.reply()?;
        if reply.code != "OK" { return Ok(reply); }
        eprintln!("SE session active for exact key {kid}; no grant issued. Keep this helper running; closing it locks all keys and revokes grants. Maximum 900 seconds; no automatic reconnect.");
        for sequence in 1u64.. {
            std::thread::sleep(Duration::from_secs(1));
            self.stream.reset(Duration::from_secs(5));
            protocol::write(&mut self.stream, &protocol::SeHeartbeat { session_id: challenge.session_id.clone(), sequence })?;
            let reply = self.reply()?;
            if reply.code != "OK" { return Ok(reply); }
        }
        Err(KeydError::Locked)
    }

    pub fn connect(path: &Path, admin: bool) -> Result<Self> {
        super::require_boundary_platform()?;
        let config = ServiceConfig::load(path)?;
        if admin && !config.admin_uids.contains(&self_uid()) {
            return Err(KeydError::Permission("ADMIN_REQUIRED".into()));
        }
        let (socket, gid) = if admin {
            (&config.admin_socket, config.admin_gid)
        } else {
            (&config.sign_socket, config.agent_gid)
        };
        let before = paths::socket(socket, config.service_uid, gid)?;
        let stream = UnixStream::connect(socket)?;
        // Authenticate first, before tty prompting or serialization of a password.
        if peer_identity(&stream)?.uid != config.service_uid {
            return Err(KeydError::Permission("SERVER_IDENTITY_MISMATCH".into()));
        }
        let after = paths::socket(socket, config.service_uid, gid)?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(KeydError::Permission("SERVER_IDENTITY_MISMATCH".into()));
        }
        Ok(Self {
            stream: DeadlineStream::new(stream, Duration::from_secs(5)),
            config,
            admin,
        })
    }

    pub fn capabilities(mut self) -> Result<Reply> {
        if self.admin {
            protocol::write(
                &mut self.stream,
                &Envelope {
                    version: VERSION,
                    request: AdminRequest::Capabilities {},
                },
            )?;
        } else {
            protocol::write(
                &mut self.stream,
                &Envelope {
                    version: VERSION,
                    request: DataRequest::Capabilities {},
                },
            )?;
        }
        self.reply()
    }

    /// Exactly one v2 request to the configured endpoint; never retries or downgrades.
    pub fn data(mut self, request: DataRequest) -> Result<Reply> {
        if self.admin {
            return Err(KeydError::Misuse("DATA_ENDPOINT_REQUIRED".into()));
        }
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request,
            },
        )?;
        self.reply()
    }

    pub fn principals(mut self) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::ListPrincipals {},
            },
        )?;
        self.reply()
    }
    pub fn catalog(mut self) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::Catalog {},
            },
        )?;
        self.reply()
    }
    pub fn prepare(mut self, change: crate::persistence::Change) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::Prepare { change },
            },
        )?;
        self.reply()
    }
    pub fn commit(mut self, operation_id: String, digest: String) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::Commit {
                    operation_id,
                    digest,
                },
            },
        )?;
        self.reply()
    }

    pub fn lock_all(mut self) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::LockAll {},
            },
        )?;
        self.reply()
    }

    /// Proof the first document of a DID whose keys are still unpublished.
    pub fn sign_first_document(
        mut self,
        vault_id: String,
        did: String,
        document: serde_json::Value,
        domain: Option<String>,
        challenge: Option<String>,
    ) -> Result<Reply> {
        self.management()?;
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::SignFirstDocument {
                    vault_id,
                    did,
                    document,
                    domain,
                    challenge,
                },
            },
        )?;
        self.reply()
    }

    pub fn complete_secret_operation(
        mut self,
        operation_id: String,
        digest: String,
        secret: Zeroizing<String>,
    ) -> Result<Reply> {
        self.management()?;
        self.stream.reset(Duration::from_secs(5));
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::CompleteSecretOperation {
                    operation_id,
                    digest,
                },
            },
        )?;
        protocol::write_secret(&mut self.stream, &secret)?;
        self.stream.reset(Duration::from_secs(30));
        self.reply()
    }

    pub fn unlock(
        mut self,
        vault_id: String,
        did: String,
        kid: String,
        passphrase: Zeroizing<String>,
    ) -> Result<Reply> {
        self.management()?;
        // Prompting may have taken time; the read/write budget starts when sending.
        self.stream.reset(Duration::from_secs(5));
        protocol::write(
            &mut self.stream,
            &Envelope {
                version: VERSION,
                request: AdminRequest::Unlock { vault_id, did, kid },
            },
        )?;
        protocol::write_secret(&mut self.stream, &passphrase)?;
        self.stream.reset(Duration::from_secs(30));
        self.reply()
    }

    fn management(&self) -> Result<()> {
        if !self.admin {
            return Err(KeydError::Permission("ADMIN_REQUIRED".into()));
        }
        Ok(())
    }

    fn reply(&mut self) -> Result<Reply> {
        let reply: Reply = protocol::read(&mut self.stream)?;
        if reply.version != VERSION {
            return Err(KeydError::Protocol("PROTOCOL_VERSION_UNSUPPORTED".into()));
        }
        if reply.code == "OK"
            && reply.instance_id.as_deref() != Some(self.config.instance_id.as_str())
        {
            return Err(KeydError::Permission("SERVER_IDENTITY_MISMATCH".into()));
        }
        if reply.code != "OK" {
            return Err(KeydError::Permission(reply.code));
        }
        Ok(reply)
    }
}
