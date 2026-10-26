//! 目录布局、原子写、权限。
//!
//! ```text
//! ~/.anpio-key/                       0700
//!   device.secret                    0600  32 字节随机 —— 第一把钥匙
//!   keys/<thumbprint>.json           0600  信封(磁盘上唯一存的东西)
//!   dids/<did-safe>.json             0644  可公开的 did:wba 文档
//!   audit/2026-10.jsonl              0600  append-only
//!   run/keyd.sock                    0600
//!   run/keyd.pid                     0600  守护进程的 pid,`stop` 读它
//!   log/serve.log                    0600  给人排查用的,和 audit/ 不是一回事
//! ```

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{KeydError, Result};

pub const DIR_MODE: u32 = 0o700;
/// 密钥信封与设备密钥:只有属主可读写。
pub const SECRET_FILE_MODE: u32 = 0o600;
/// DID 文档本来就是给人抓的。
pub const PUBLIC_FILE_MODE: u32 = 0o644;

pub struct KeydLayout {
    root: PathBuf,
}

impl KeydLayout {
    /// 模式 S(单机单用户):`~/.anpio-key`。
    pub fn user_default() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| KeydError::Protocol("HOME is not set; use --root".into()))?;
        Ok(Self::at(PathBuf::from(home).join(".anpio-key")))
    }

    /// 模式 S 系统服务:`/var/lib/anpio-key/users/<uid>` —— 每人一个命名空间。
    pub fn system(uid: u32) -> Result<Self> {
        Ok(Self::at(
            PathBuf::from("/var/lib/anpio-key/users").join(uid.to_string()),
        ))
    }

    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 建目录并**显式**盖上权限位 —— 不依赖 umask,umask 是进程环境的,
    /// 不该决定密钥目录的权限。
    pub fn ensure(&self) -> Result<()> {
        for dir in [
            self.root.clone(),
            self.keys_dir(),
            self.dids_dir(),
            self.audit_dir(),
            self.run_dir(),
            self.log_dir(),
        ] {
            fs::create_dir_all(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(DIR_MODE))?;
        }
        Ok(())
    }

    pub fn device_secret_path(&self) -> PathBuf {
        self.root.join("device.secret")
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.root.join("keys")
    }

    /// 信封路径。`thumbprint` 来自 DID 字符串这类外部输入,必须挡住路径穿越。
    pub fn key_path(&self, thumbprint: &str) -> Result<PathBuf> {
        if !is_safe_thumbprint(thumbprint) {
            return Err(KeydError::Protocol(format!(
                "refusing unsafe thumbprint for a filename: {thumbprint:?}"
            )));
        }
        Ok(self.keys_dir().join(format!("{thumbprint}.json")))
    }

    pub fn dids_dir(&self) -> PathBuf {
        self.root.join("dids")
    }

    pub fn did_path(&self, did: &str) -> PathBuf {
        self.dids_dir().join(format!("{}.json", did_safe(did)))
    }

    pub fn audit_dir(&self) -> PathBuf {
        self.root.join("audit")
    }

    /// 迁移/注销时用来串行化"读→比→写"的那把锁。
    ///
    /// **不是锁文档本身。** `write_atomic` 是 rename,锁住旧 inode 一点用
    /// 都没有:另一个进程照样能在旧 inode 上拿锁,然后 rename 覆盖掉我们刚
    /// 写的东西。锁必须是一把谁都不动的文件。
    pub fn did_lock_path(&self, did: &str) -> PathBuf {
        self.dids_dir().join(format!("{}.lock", did_safe(did)))
    }

    /// 扫出磁盘上所有 DID 文档。迁移的环检测靠它 —— 只知道旧文档是不够的。
    pub fn list_did_paths(&self) -> Result<Vec<PathBuf>> {
        let dir = self.dids_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                out.push(path);
            }
        }
        out.sort();
        Ok(out)
    }

    /// `year_month` 形如 `2026-10`。
    pub fn audit_path(&self, year_month: &str) -> PathBuf {
        self.audit_dir().join(format!("{year_month}.jsonl"))
    }

    pub fn run_dir(&self) -> PathBuf {
        self.root.join("run")
    }

    pub fn sock_path(&self) -> PathBuf {
        self.run_dir().join("keyd.sock")
    }

    /// 守护进程写自己 pid 的地方。`stop` 读它。
    ///
    /// 放在 `run/` 里:它和 socket 一样是**运行时状态**,进程一没就该没。
    pub fn pid_path(&self) -> PathBuf {
        self.run_dir().join("keyd.pid")
    }

    /// 守护进程的日志目录。
    ///
    /// **和 `audit/` 严格分开。** 审计那边是哈希链加锚,是防篡改的证据;
    /// 这边是给人和 agent 排查用的流水。两样东西写进同一个文件,等于让
    /// "日志里有这一条"和"这件事发生过"重新变成一回事 —— 那正是审计
    /// 存在的理由的反面。
    pub fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }

    pub fn log_path(&self) -> PathBuf {
        self.log_dir().join("serve.log")
    }

    /// 扫出磁盘上所有信封。损坏的文件不跳过 —— 静默忽略一个读不懂的
    /// 密钥文件,等于让用户以为自己的钥匙不见了。
    pub fn list_key_paths(&self) -> Result<Vec<PathBuf>> {
        let dir = self.keys_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                out.push(path);
            }
        }
        out.sort();
        Ok(out)
    }
}

/// 原子写:同目录临时文件 → fsync → rename → fsync 目录。
///
/// 半截的文件比没有文件更糟:它看起来像个密钥,解不开,而且原始内容已经没了。
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| KeydError::Protocol("target path has no parent".into()))?;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))?;

    let tmp = dir.join(format!(
        ".tmp-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ));

    // 从创建那一刻就是 0600 —— 不存在"先建后 chmod"的泄露窗口。
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, path)?;
    // 让改名本身也落盘,否则崩溃后可能看到旧文件。
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// 读一个 0600 的文件,并确认它确实只有属主可读写。
///
/// 权限被人放宽过就拒绝 —— 一个组内可读的密钥文件是已经发生的事故。
pub fn read_secret_file(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeydError::Protocol(format!(
            "{} is mode {mode:o}; refusing to read a secret that is not 0600",
            path.display()
        )));
    }
    Ok(fs::read(path)?)
}

/// 指纹当文件名时的白名单。`e1_`(签名键)或 `x1_`(协商键)前缀 + base58btc 字母表。
fn is_safe_thumbprint(t: &str) -> bool {
    let Some(rest) = t.strip_prefix("e1_").or_else(|| t.strip_prefix("x1_")) else {
        return false;
    };
    !rest.is_empty()
        && rest.len() <= 128
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// 把 DID 变成安全文件名。`:` 是 DID 里最常见的字符,单独处理;
/// 其余不在白名单的一律换成 `_`。
pub fn did_safe(did: &str) -> String {
    did.chars()
        .map(|c| match c {
            ':' => '_',
            c if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' => c,
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_safe_flattens_colons() {
        assert_eq!(
            did_safe("did:wba:example.com:user:alice:e1_abc"),
            "did_wba_example.com_user_alice_e1_abc"
        );
    }

    #[test]
    fn did_safe_cannot_escape_the_directory() {
        // 目录穿越必须被压平。
        assert_eq!(did_safe("../../etc/passwd"), ".._.._etc_passwd");
        assert!(!did_safe("did:wba:x/../y").contains('/'));
    }

    #[test]
    fn thumbprint_path_rejects_traversal() {
        let layout = KeydLayout::at(PathBuf::from("/tmp/does-not-matter"));
        assert!(layout.key_path("e1_../../etc/passwd").is_err());
        assert!(layout.key_path("not-a-thumbprint").is_err());
        assert!(layout.key_path("e1_okBASE58").is_ok());
    }

    #[test]
    fn atomic_write_then_read_back() {
        let dir = std::env::temp_dir().join(format!("keyd-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let layout = KeydLayout::at(dir.clone());
        layout.ensure().unwrap();

        let target = layout.key_path("e1_test").unwrap();
        write_atomic(&target, b"hello", SECRET_FILE_MODE).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"hello");

        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, SECRET_FILE_MODE, "secret file must land as 0600");

        // 临时文件不许留下。
        let leftovers: Vec<_> = fs::read_dir(layout.keys_dir())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "atomic write left a temp file behind");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn world_readable_secret_is_refused() {
        let dir = std::env::temp_dir().join(format!("keyd-perm-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("loose.secret");
        fs::write(&f, b"x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(read_secret_file(&f).is_err(), "0644 secret must be refused");
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_secret_file(&f).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }
}
