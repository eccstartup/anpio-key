use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::paths;
use crate::error::{KeydError, Result};
use crate::principal::{validate_uuid, Principal};

pub const DEFAULT_CONFIG: &str = "/etc/anpio-key/service.json";

/// Root-owned deployment config. Principals are initialization inputs only;
/// live mutable principal state is read from SQLite on each data request.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub schema_version: u32,
    pub mode: String,
    pub instance_id: String,
    pub service_uid: u32,
    pub admin_uids: Vec<u32>,
    pub agent_gid: u32,
    pub admin_gid: u32,
    pub state_dir: PathBuf,
    pub sign_socket: PathBuf,
    pub admin_socket: PathBuf,
    pub principals: Vec<Principal>,
    pub vault_ids: Vec<String>,
    #[serde(default)]
    pub limits: super::limits::Limits,
    /// 新的签名路一律默认关。开关只决定数据平面是否接受该操作,
    /// 不改变已有的 HTTP 签名路径。
    #[serde(default)]
    pub features: Features,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Features {
    /// `SIGN_ORIGIN_PROOF`。默认关,开的时候启动审计里有一条 FEATURES。
    #[serde(default)]
    pub sign_origin_proof: bool,
}

impl ServiceConfig {
    pub fn protected_supported(&self) -> bool {
        super::protected_build_supported() && self.mode == "linux-protected-v1"
    }

    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        if self.schema_version != 1
            || !matches!(
                self.mode.as_str(),
                "linux-boundary-preview" | "linux-protected-v1" | "macos-boundary-preview"
            )
        {
            return Err(invalid("unsupported config version or mode"));
        }
        if (self.mode.starts_with("linux-") && !cfg!(target_os = "linux"))
            || (self.mode.starts_with("macos-") && !cfg!(target_os = "macos"))
        {
            return Err(invalid("deployment mode does not match this platform"));
        }
        if !validate_uuid(&self.instance_id)
            || self.service_uid == 0
            || self.service_uid == u32::MAX
            || self.admin_uids.is_empty()
            || self.agent_gid == 0
            || self.admin_gid == 0
            || self.agent_gid == self.admin_gid
            || self.agent_gid == u32::MAX
            || self.admin_gid == u32::MAX
        {
            return Err(invalid("invalid installation identity or groups"));
        }
        let admins: BTreeSet<_> = self.admin_uids.iter().copied().collect();
        if admins.len() != self.admin_uids.len()
            || admins.contains(&self.service_uid)
            || admins.contains(&u32::MAX)
        {
            return Err(invalid("administrators must be distinct from the service"));
        }
        let mut uids = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for p in &self.principals {
            if p.uid == 0
                || p.uid == self.service_uid
                || p.uid == u32::MAX
                || admins.contains(&p.uid)
                || !uids.insert(p.uid)
                || !ids.insert(&p.principal_id)
                || !validate_uuid(&p.principal_id)
                || p.generation == 0
            {
                return Err(invalid("principal identities overlap or are invalid"));
            }
        }
        let mut vaults = BTreeSet::new();
        if self
            .vault_ids
            .iter()
            .any(|id| !validate_uuid(id) || !vaults.insert(id))
        {
            return Err(invalid("invalid or duplicate vault ID"));
        }
        for path in [&self.state_dir, &self.sign_socket, &self.admin_socket] {
            paths::validate_absolute(path)?;
        }
        if self.sign_socket == self.admin_socket
            || self.sign_socket.parent() == self.admin_socket.parent()
            || self.sign_socket.starts_with(&self.state_dir)
            || self.admin_socket.starts_with(&self.state_dir)
        {
            return Err(invalid(
                "state and separate socket directories must be distinct",
            ));
        }
        Ok(())
    }

    /// Neither environment variables nor a socket override participate in trust.
    pub fn load(path: &Path) -> Result<Self> {
        paths::validate_chain(path, &[0], false)?;
        let file = File::options()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)?;
        paths::validate_file_metadata(&file.metadata()?, &[0], false)?;
        let mut bytes = Vec::new();
        file.take(65_537).read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(invalid("config exceeds 64 KiB"));
        }
        let config: Self = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("malformed service configuration"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn vault(&self, id: &str) -> Result<PathBuf> {
        if !self.vault_ids.iter().any(|known| known == id) {
            return Err(invalid("unknown vault ID"));
        }
        Ok(self.state_dir.join("vaults").join(id))
    }
}

fn invalid(message: &str) -> KeydError {
    KeydError::Misuse(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn fixture() -> ServiceConfig {
        ServiceConfig {
            schema_version: 1,
            mode: if cfg!(target_os = "macos") {
                "macos-boundary-preview"
            } else {
                "linux-boundary-preview"
            }
            .into(),
            instance_id: "12345678-1234-4234-8234-123456789abc".into(),
            service_uid: 1001,
            admin_uids: vec![0, 1002],
            agent_gid: 1003,
            admin_gid: 1004,
            state_dir: "/var/lib/anpio-key".into(),
            sign_socket: "/run/anpio-key/sign/sign.sock".into(),
            admin_socket: "/run/anpio-key/admin/admin.sock".into(),
            principals: vec![Principal {
                principal_id: "12345678-1234-4234-8234-123456789abd".into(),
                uid: 1005,
                generation: 1,
                enabled: true,
            }],
            vault_ids: vec![],
            limits: Default::default(),
            features: Default::default(),
        }
    }

    #[test]
    fn protected_mode_requires_supported_build_and_explicit_opt_in() {
        let mut config = fixture();
        assert!(!config.protected_supported());
        config.mode = "linux-protected-v1".into();
        assert_eq!(config.validate().is_ok(), cfg!(target_os = "linux"));
        assert_eq!(
            config.protected_supported(),
            super::super::protected_build_supported()
        );
        config.mode = "unknown-mode".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn macos_preview_never_claims_protected_support() {
        let mut config = fixture();
        config.mode = "macos-boundary-preview".into();
        assert_eq!(config.validate().is_ok(), cfg!(target_os = "macos"));
        assert!(!config.protected_supported());
        config.mode = "macos-protected-v1".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_overlapping_identities_and_paths() {
        let valid = fixture();
        valid.validate().unwrap();
        for uid in [0, 1001, 1002, u32::MAX] {
            let mut config = valid.clone();
            config.principals[0].uid = uid;
            assert!(config.validate().is_err());
        }
        let mut config = valid.clone();
        config.principals.push(config.principals[0].clone());
        assert!(config.validate().is_err());
        let mut config = valid.clone();
        config.admin_socket = config.sign_socket.clone();
        assert!(config.validate().is_err());
        let mut config = valid;
        config.state_dir = "/var/lib/../lib/anpio-key".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn strict_schema_and_disabled_principal() {
        let config = fixture();
        let mut value = serde_json::to_value(&config).unwrap();
        value["unexpected"] = true.into();
        assert!(serde_json::from_value::<ServiceConfig>(value).is_err());
        let mut principals = config.principals;
        assert!(crate::principal::resolve(&principals, principals[0].uid).is_ok());
        principals[0].enabled = false;
        assert!(crate::principal::resolve(&principals, principals[0].uid).is_err());
        assert!(config.vault_ids.is_empty());
    }
}
