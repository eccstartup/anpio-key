//! Test-only cross-process Secure Enclave persistence probe.
//!
//! This is not a release command. It exists so the U3 acceptance can make the
//! claim that actually matters with two separate processes:
//!
//! ```text
//! se-persistence create STATE acceptance-<uuid>   # process A
//! se-persistence open STATE                       # process B
//! se-persistence delete STATE                     # process C
//! ```
//!
//! `create` writes the envelope's public locator (the keychain label), its
//! ECDH ciphertext and a SHA-256 of the derived HS. No key material is written:
//! the HS digest is one-way and exists only so `open` can prove it re-derived
//! the same value from the same Secure Enclave key. `open` deliberately runs in
//! a fresh process; that is the whole point.
//!
//! Labels are constrained to `acceptance-*` inside the backend, so this probe
//! cannot touch a real envelope's key even if its state file is tampered with.

#[cfg(not(all(
    target_os = "macos",
    feature = "hardware-se",
    feature = "se-acceptance"
)))]
fn main() {
    eprintln!("se-persistence requires macOS with --features hardware-se,se-acceptance");
    std::process::exit(2);
}

#[cfg(all(
    target_os = "macos",
    feature = "hardware-se",
    feature = "se-acceptance"
))]
fn main() {
    if let Err(error) = macos::run() {
        eprintln!("se-persistence: {error}");
        std::process::exit(1);
    }
}

#[cfg(all(
    target_os = "macos",
    feature = "hardware-se",
    feature = "se-acceptance"
))]
mod macos {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use anpio_key::keystore::hardware::se::{
        acceptance_create, acceptance_delete, acceptance_open, acceptance_open_checked,
    };
    use anpio_key::keystore::record::HardwareRoot;
    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};

    const MAX_STATE: u64 = 64 * 1024;
    const STATE_SCHEMA: u8 = 1;

    #[derive(Debug, Serialize, Deserialize)]
    struct State {
        schema: u8,
        tag_hint: String,
        root: HardwareRoot,
        ciphertext_b64: String,
        hs_sha256: String,
    }

    pub fn run() -> Result<(), String> {
        // Diagnose OS keychain identity separately from the Unix effective UID.
        // No key material, password or entitlement secret is included.
        eprintln!("SE_CONTEXT {}", process_context()?);
        let mut args = std::env::args().skip(1);
        match args.next().as_deref() {
            Some("create") => {
                let state = path(args.next(), "STATE")?;
                let tag = args.next().ok_or("create requires TAG")?;
                no_more(args)?;
                create(&state, &tag)
            }
            Some("open") => {
                let state = path(args.next(), "STATE")?;
                no_more(args)?;
                open(&state, false)
            }
            Some("open-checked") => {
                let state = path(args.next(), "STATE")?;
                no_more(args)?;
                open(&state, true)
            }
            Some("delete") => {
                let state = path(args.next(), "STATE")?;
                no_more(args)?;
                delete(&state)
            }
            Some("label") => {
                let state = path(args.next(), "STATE")?;
                no_more(args)?;
                let state = read_state(&state)?;
                println!("{}", state.tag_hint);
                Ok(())
            }
            other => Err(format!(
                "expected create STATE TAG, open STATE, delete STATE or label STATE; got {other:?}"
            )),
        }
    }

    fn process_context() -> Result<serde_json::Value, String> {
        #[link(name = "bsm")]
        unsafe extern "C" {
            fn getauid(uid: *mut u32) -> i32;
        }
        #[link(name = "Security", kind = "framework")]
        unsafe extern "C" {
            fn SessionGetInfo(session: u32, actual: *mut u32, attributes: *mut u32) -> i32;
        }
        let mut audit_uid = u32::MAX;
        let mut session = 0;
        let mut attributes = 0;
        if unsafe { getauid(&mut audit_uid) } != 0
            || unsafe { SessionGetInfo(u32::MAX, &mut session, &mut attributes) } != 0
        {
            return Err("could not read kernel audit identity/session".into());
        }
        Ok(serde_json::json!({
            "uid": nix::unistd::getuid().as_raw(),
            "euid": nix::unistd::geteuid().as_raw(),
            "audit_uid": audit_uid,
            "audit_session": session,
            "session_attributes": attributes,
        }))
    }

    fn path(value: Option<String>, name: &str) -> Result<PathBuf, String> {
        value
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing {name}"))
    }

    fn no_more(mut args: impl Iterator<Item = String>) -> Result<(), String> {
        match args.next() {
            Some(extra) => Err(format!("unexpected argument {extra:?}")),
            None => Ok(()),
        }
    }

    fn create(path: &Path, tag: &str) -> Result<(), String> {
        let sealed = acceptance_create(tag).map_err(|error| error.to_string())?;
        let digest = sealed.hs.expose(|bytes| hex(&Sha256::digest(bytes)));
        let state = State {
            schema: STATE_SCHEMA,
            tag_hint: tag.to_string(),
            root: sealed.root,
            ciphertext_b64: base64::engine::general_purpose::STANDARD.encode(&sealed.ciphertext),
            hs_sha256: digest,
        };
        if let Err(error) = write_state(path, &state) {
            // The key is already in the keychain. Do not leave an orphan behind
            // just because the public state file could not be written.
            let _ = acceptance_delete(&state.root);
            return Err(error);
        }
        println!("CREATED {tag}");
        Ok(())
    }

    fn open(path: &Path, checked: bool) -> Result<(), String> {
        let state = read_state(path)?;
        let ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&state.ciphertext_b64)
            .map_err(|error| format!("state ciphertext is not base64: {error}"))?;
        let hs = if checked {
            acceptance_open_checked(&state.root, &ciphertext)
        } else {
            acceptance_open(&state.root, &ciphertext)
        }.map_err(|error| error.to_string())?;
        let actual = hs.expose(|bytes| hex(&Sha256::digest(bytes)));
        if actual != state.hs_sha256 {
            return Err(format!(
                "the Secure Enclave reopened label {:?}, but the derived HS differs from the one \
                 created by the other process",
                state.tag_hint
            ));
        }
        println!("PASS {}", state.tag_hint);
        Ok(())
    }

    fn delete(path: &Path) -> Result<(), String> {
        let state = read_state(path)?;
        acceptance_delete(&state.root).map_err(|error| error.to_string())?;
        println!("DELETED {}", state.tag_hint);
        Ok(())
    }

    fn write_state(path: &Path, state: &State) -> Result<(), String> {
        let body = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
        file.write_all(&body)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write {}: {error}", path.display()))
    }

    fn read_state(path: &Path) -> Result<State, String> {
        let file =
            File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
        let mut body = Vec::new();
        file.take(MAX_STATE + 1)
            .read_to_end(&mut body)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if body.len() as u64 > MAX_STATE {
            return Err(format!("{} is too large", path.display()));
        }
        let state: State = serde_json::from_slice(&body)
            .map_err(|error| format!("{} is not a state file: {error}", path.display()))?;
        if state.schema != STATE_SCHEMA {
            return Err(format!(
                "{} has schema {}, expected {STATE_SCHEMA}",
                path.display(),
                state.schema
            ));
        }
        let HardwareRoot::SecureEnclave { tag } = &state.root else {
            return Err("acceptance state does not name a Secure Enclave key".into());
        };
        if tag != &format!("anp-keyd/{}", state.tag_hint) {
            return Err("acceptance state label and tag disagree".into());
        }
        Ok(state)
    }

    fn hex(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
        }
        text
    }
}
