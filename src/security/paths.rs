//! Trust paths are absolute, symlink-free, and not writable by Agents.
use std::fs::{Metadata, OpenOptions};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use crate::error::{KeydError, Result};

fn denied(path: &Path) -> KeydError {
    KeydError::Permission(format!("untrusted protected path: {}", path.display()))
}

pub fn validate_absolute(path: &Path) -> Result<()> {
    let spelling = path.to_string_lossy();
    if !path.is_absolute()
        || spelling.contains("//")
        || spelling
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(denied(path));
    }
    Ok(())
}

pub fn validate_file_metadata(meta: &Metadata, owners: &[u32], directory: bool) -> Result<()> {
    if !owners.contains(&meta.uid())
        || meta.mode() & 0o022 != 0
        || (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
    {
        return Err(KeydError::Permission(
            "untrusted owner, mode or file type".into(),
        ));
    }
    Ok(())
}

pub fn validate_chain(path: &Path, owners: &[u32], directory: bool) -> Result<()> {
    validate_absolute(path)?;
    let mut current = PathBuf::from("/");
    validate_file_metadata(&std::fs::symlink_metadata(&current)?, owners, true)?;
    reject_extended_acl(&current)?;
    for component in path.components().skip(1) {
        current.push(component);
        let meta = std::fs::symlink_metadata(&current)?;
        validate_file_metadata(&meta, owners, current != path || directory)?;
        reject_extended_acl(&current)?;
    }
    Ok(())
}

pub fn state_directory(path: &Path, service_uid: u32) -> Result<()> {
    validate_chain(path, &[0, service_uid], true)?;
    let meta = std::fs::symlink_metadata(path)?;
    if meta.uid() != service_uid || meta.mode() & 0o777 != 0o700 {
        return Err(denied(path));
    }
    Ok(())
}

pub fn socket_parent(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| denied(path))?;
    validate_chain(parent, &[0, uid], true)?;
    let meta = std::fs::symlink_metadata(parent)?;
    if meta.uid() != uid || meta.gid() != gid || meta.mode() & 0o777 != 0o750 {
        return Err(denied(parent));
    }
    Ok(())
}

pub fn socket(path: &Path, uid: u32, gid: u32) -> Result<Metadata> {
    socket_parent(path, uid, gid)?;
    let meta = std::fs::symlink_metadata(path)?;
    reject_extended_acl(path)?;
    if !meta.file_type().is_socket()
        || meta.uid() != uid
        || meta.gid() != gid
        || meta.mode() & 0o777 != 0o660
    {
        return Err(denied(path));
    }
    Ok(meta)
}

pub fn instance_lock(state: &Path, service_uid: u32) -> Result<nix::fcntl::Flock<std::fs::File>> {
    state_directory(state, service_uid)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(state.join("service.lock"))?;
    let meta = file.metadata()?;
    validate_file_metadata(&meta, &[service_uid], false)?;
    if meta.mode() & 0o777 != 0o600 || meta.nlink() != 1 {
        return Err(denied(state));
    }
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| KeydError::Misuse("another service holds the state lock".into()))
}

/// Legacy writers and daemons hold a shared maintenance lease. Offline cutover
/// requires its exclusive counterpart and therefore cannot race this version.
pub fn legacy_lease(root: &Path) -> Result<nix::fcntl::Flock<std::fs::File>> {
    deny_managed_directory(root)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(root.join(".maintenance.lock"))?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != crate::daemon::self_uid()
        || meta.mode() & 0o777 != 0o600
    {
        return Err(denied(root));
    }
    let lease = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockSharedNonblock)
        .map_err(|_| KeydError::Misuse("vault is in offline maintenance".into()))?;
    // The marker may have appeared while waiting for or opening the lock.
    deny_managed_directory(root)?;
    Ok(lease)
}

/// Legacy local commands must never act as a maintenance backdoor into a
/// managed vault, including when --root uses a symlink or a relative spelling.
pub fn deny_managed_directory(path: &Path) -> Result<()> {
    let mut existing = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    while !existing.exists() {
        if !existing.pop() {
            return Ok(());
        }
    }
    let existing = existing.canonicalize()?;
    for ancestor in existing.ancestors() {
        if ancestor.join(".anpio-key-managed").try_exists()?
            || ancestor.join("state.sqlite").try_exists()?
        {
            return Err(KeydError::Permission(
                "managed vault requires authenticated admin client".into(),
            ));
        }
    }
    Ok(())
}

/// POSIX mode bits do not describe macOS extended ACL grants. Preview deployments
/// conservatively reject every extended entry, including inherited/deny entries.
#[cfg(target_os = "macos")]
fn reject_extended_acl(path: &Path) -> Result<()> {
    use std::ffi::{c_void, CString};
    use std::os::unix::ffi::OsStrExt;
    unsafe extern "C" {
        fn acl_get_file(path: *const i8, kind: i32) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, entry_id: i32, entry: *mut *mut c_void) -> i32;
        fn acl_free(object: *mut c_void) -> i32;
    }
    let name = CString::new(path.as_os_str().as_bytes()).map_err(|_| denied(path))?;
    // Darwin ACL_TYPE_EXTENDED=0x100, ACL_FIRST_ENTRY=0. A valid empty ACL
    // returns -1 with EINVAL when requesting its first entry (Darwin acl_get_entry).
    let acl = unsafe { acl_get_file(name.as_ptr(), 0x100) };
    if acl.is_null() {
        // Darwin returns ENOENT for an existing vnode with no extended ACL.
        // Recheck existence so a missing path is never accepted as ACL-free.
        if std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::ENOENT) {
            std::fs::symlink_metadata(path)?;
            return Ok(());
        }
        return Err(denied(path));
    }
    let mut entry = std::ptr::null_mut();
    let status = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = std::io::Error::last_os_error();
    unsafe {
        acl_free(acl);
    }
    if status == -1 && error.raw_os_error() == Some(nix::libc::EINVAL) {
        Ok(())
    } else {
        Err(denied(path))
    }
}
#[cfg(not(target_os = "macos"))]
fn reject_extended_acl(_: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    #[test]
    fn extended_acl_cannot_override_trusted_mode_bits() {
        let path = std::env::temp_dir().join(format!(
            "keyd-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        {
            reject_extended_acl(&path).unwrap();
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective()).unwrap().unwrap().name;
            let acl = format!("user:{user} allow read,write");
            assert!(std::process::Command::new("/bin/chmod")
                .args(["+a", &acl])
                .arg(&path)
                .status()
                .unwrap()
                .success());
            assert!(reject_extended_acl(&path).is_err());
            assert!(std::process::Command::new("/bin/chmod")
                .arg("-N")
                .arg(&path)
                .status()
                .unwrap()
                .success());
            reject_extended_acl(&path).unwrap();
        }
        std::fs::remove_dir(path).unwrap();
    }
}
